"""
https://github.com/wwarne/logsreader
"""
import re
import os
import gzip
import time
import argparse
from datetime import datetime
from collections import namedtuple
from hashlib import md5

import pytz
import dateutil.parser
from tzlocal import get_localzone

# =============== SETTINGS ===============
#  All times of the events will be displayed in this timezone
OUTPUT_TIMEZONE = 'Europe/Moscow'
DATABASE = {
    # db_type can be 'postgresql' or 'sqlite'. If sqlite then host,port,user etc - doesn't matter
    'db_type': 'postgresql',
    'host': '192.168.1.216',
    'port': '5432',
    'user': 'django',
    'password': 'djangotest',
    'database': 'logs',
}
LOG_SETTINGS = {
    'security_log_dir': '/var/log/',
    'security_log_name': 'auth.log',
    'apt_log_dir': '/var/log/apt/',
    'apt_log_name': 'history.log'
}
# =============== SETTINGS IS OVER ===============
if DATABASE.get('db_type') == 'postgresql':
    import psycopg2
else:
    import sqlite3

# =============== REGULAR EXPRESSIONS TO SEARCH EVENTS ===============
failed_login_re = re.compile(r'^([a-z]{3}\s+[0-9]{1,2}\s+[0-9:]+).*Failed password for ([^ ]+) from ([^ ]+)', re.I)
sudo_command_re = re.compile(r'^([a-z]{3}\s+[0-9]{1,2}\s+[0-9:]+).*sudo:\s+([^ ]+).*COMMAND=(.*)', re.I)
auth_with_key_re = re.compile(r'^([a-z]{3}\s+[0-9]{1,2}\s+[0-9:]+).*'
                              r'Accepted publickey for ([^ ]+) from ([^ ]+) (port [0-9]+ ).*:(.+)', re.I)
auth_with_password_re = re.compile(r'^([a-z]{3}\s+[0-9]{1,2}\s+[0-9:]+).*'
                                   r'Accepted password for ([^ ]+) from ([^ ]+) (port [0-9]+ )', re.I)
apt_get_commands_re = re.compile(r'Commandline:.*(install|remove) (.*)', re.I)

Event = namedtuple('Event', ['date', 'type', 'username', 'user_ip', 'details'])
TYPES = {
    'AUTH_KEY': 1,
    'AUTH_PASSWORD': 2,
    'AUTH_FAILED': 3,
    'SUDO_COMMAND': 4,
    'INSTALL_PACKAGE': 5,
    'REMOVE_PACKAGE': 6,
}


class LogsFinderAndReader:
    """
    Scans directory `logdir`, finds all files that include the `logname`.
    Alternately opens them, and returns the lines from them one-by-one.
    """

    def __init__(self, logdir, logname):
        """

        :param logdir: Directory where to search for logs
        :param logname: Log file name
        """
        self.logs_dir = logdir
        self.logname = logname
        self.logfiles = []
        self.search_log_files()

    def search_log_files(self):
        for (dirpath, dirnames, filenames) in os.walk(self.logs_dir):
            for filename in filenames:
                if self.logname in filename:
                    self.logfiles.append(os.path.join(dirpath, filename))

    def get_lines(self):
        """
        Opens all log files. Supports .gz files (logrotate)
        :return: strings from file, one after one
        """
        for one_file in self.logfiles:
            if one_file.endswith('.gz'):
                try:
                    with gzip.open(one_file, mode='rt') as curr_file:
                        for one_line_from_file in curr_file:
                            yield one_line_from_file
                except EnvironmentError:
                    print('Can\'t read {}'.format(one_file))
            else:
                try:
                    with open(one_file) as current_file:
                        for one_line_from_file in current_file:
                            yield one_line_from_file
                except EnvironmentError:
                    print('Can\'t read {}'.format(one_file))


class PostgresConnector:
    def __init__(self, db_settings):
        """
        :param db_settings: A dict with host, port, user, password, database parameters
        """
        self.conn = psycopg2.connect(**db_settings)
        self.check_tables_exists()

    def check_tables_exists(self):
        """
        Check if there is events table in the database and create a new table if not so.
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name=%s)', ('events',))
        if not cursor.fetchone()[0]:
            cursor.execute(
                """
                CREATE TABLE events(
                id serial primary key,
                event_time timestamp with time zone NOT NULL,
                event_type integer NOT NULL,
                event_user character varying(200),
                user_ip inet,
                description text,
                event_hash uuid UNIQUE
                );
                """)
            self.conn.commit()
        cursor.close()

    @staticmethod
    def prepare_data(event_data):
        """
        Converts namedtuple Event to a simple tuple. Convert date to a UTC timezone
        Calculate unique hash for event/
        :param event_data: Event namedtuple
        :return: Tuple with all the data and unique hash value.
        """
        data = (convert_str_to_utc_datetime(event_data.date), event_data.type,
                event_data.username, event_data.user_ip, event_data.details)
        data_str = str(data)
        data_hash = md5(data_str.encode('utf-8')).hexdigest()
        return data + (data_hash,)

    def save(self, event_data):
        new_data = self.prepare_data(event_data)
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO events (event_time, event_type, event_user, user_ip, description, event_hash)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                """, new_data)
            self.conn.commit()
        except:
            self.conn.rollback()
        finally:
            cursor.close()

    def get_events(self, date_filter=None, timezone=None):
        cursor = self.conn.cursor()
        if date_filter:
            addition = ' WHERE event_time >=%s'
            date_filter = convert_str_to_utc_datetime(date_filter, from_timezone=timezone)
            params = (date_filter,)
        else:
            addition = ''
            params = tuple()
        query = """SELECT event_time, event_type, event_user, user_ip, description
                   FROM events {}
                   ORDER BY event_time ASC;""".format(addition)
        cursor.execute(query, params)
        for record in cursor:
            yield record
        cursor.close()


class SqliteConnector:
    def __init__(self, db_settings=None):
        """

        :param db_settings:
        """
        self.server_timezone = get_localzone()
        self.conn = sqlite3.connect('system_events.sqlite')
        self.check_tables_exists()

    def check_tables_exists(self):
        """
        Check if there is events table in the database and create a new table if not so.
        :return:
        """
        cursor = self.conn.cursor()
        cursor.executescript(
            """
            CREATE TABLE IF NOT EXISTS events
            (
            id INTEGER PRIMARY KEY,
            event_time INTEGER ,
            event_type INTEGER NOT NULL,
            event_user TEXT,
            user_ip TEXT,
            description TEXT,
            event_hash TEXT
            );
        """)
        self.conn.commit()
        cursor.close()

    def convert_string_to_timestamp_utc(self, date_string, from_timezone):
        """
        Converts date from string to a timestamp object in UTC timezone
        :param date_string: String representation of date and time
        :return: Timestamp
        """
        event_date = dateutil.parser.parse(date_string)
        if from_timezone:
            self.server_timezone = from_timezone
        event_date = self.server_timezone.localize(event_date)
        return time.mktime(event_date.timetuple())

    @staticmethod
    def convert_timestamp_to_utc_datetime(timestamp_data):
        """
        Converts timestamp string to a datetime object
        """
        timestamp_data = int(timestamp_data)
        return datetime.fromtimestamp(int(timestamp_data), tz=pytz.UTC)

    def prepare_data(self, event_data):
        """
        Converts namedtuple Event to a simple tuple. Convert date to a UTC timezone and then to unix time
        Calculate unique hash for it
        :param event_data: Event namedtuple
        :return: Tuple with all data and unique hash value.
        """
        data = (self.convert_string_to_timestamp_utc(event_data.date), event_data.type,
                event_data.username, event_data.user_ip, event_data.details)
        data_str = str(data)
        data_hash = md5(data_str.encode('utf-8')).hexdigest()
        return data + (data_hash,)

    def save(self, event_data):
        new_data = self.prepare_data(event_data)
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO events (event_time, event_type, event_user, user_ip, description, event_hash)
                VALUES (?, ?, ?, ?, ?, ?)
                """, new_data)
            self.conn.commit()
        except:
            self.conn.rollback()
        finally:
            cursor.close()

    def get_events(self, date_filter=None, timezone=None):
        cursor = self.conn.cursor()
        if date_filter:
            addition = ' WHERE event_time >=?'
            params = (self.convert_string_to_timestamp_utc(date_filter, from_timezone=timezone),)
        else:
            addition = ''
            params = tuple()
        query = """SELECT event_time, event_type, event_user, user_ip, description
                   FROM events {}
                   ORDER BY event_time ASC;""".format(addition)
        cursor.execute(query, params)
        # Before return result - convert timestamp to a datetime object.
        for record in cursor:
            yield (self.convert_timestamp_to_utc_datetime(record[0]),) + record[1:]
        cursor.close()


def convert_str_to_utc_datetime(date_string, from_timezone=None):
    if not from_timezone:
        server_timezone = get_localzone()
    else:
        server_timezone = from_timezone
    try:
        event_date = dateutil.parser.parse(date_string)
    except ValueError:
        print('Wrong date string  {}'.format(date_string))
        return
    # Attach server time zone to this datetime
    event_date = server_timezone.localize(event_date)
    # Convert to the UTC time
    return event_date.astimezone(pytz.UTC)


def create_parser():
    """
    Check the command-line parameters, displays help on using the script
    :return: ArgumentParser object
    """
    main_parser = argparse.ArgumentParser(description='Parse, save and view some system events',
                                          epilog='Dmitry Plevkov 2016.')
    subparsers = main_parser.add_subparsers(dest='command', title='Available commands',
                                            description='This script can run in two different modes.')
    read_parser = subparsers.add_parser('parse', help='Parse logfiles and save results to a database.')
    show_parser = subparsers.add_parser('show', help='Show events from a database.(use show -h for help)')
    show_parser.add_argument('-d', '--date',
                             metavar='date/datetime (year-month-day)',
                             help='Date since which you want events to be displayed .')
    return main_parser


def get_event_from_string_auth(line):
    auth_with_password = auth_with_password_re.findall(line)
    if auth_with_password:
        # [('Jul  4 18:07:48', 'warner', '192.168.1.6', 'port 19399 ')]
        raw_event_data = auth_with_password[0]
        final_event = Event(date=raw_event_data[0], type=TYPES['AUTH_PASSWORD'], username=raw_event_data[1],
                            user_ip=raw_event_data[2],
                            details=raw_event_data[3])
        return final_event
    auth_with_key = auth_with_key_re.findall(line)
    if auth_with_key:
        # [('Jul  4 10:13:22', 'root', '91.215.191.84', 'port 3231 ', 'UVlLoEzqyFMH7hebn1mLU1K77jwWz51Htt6D2qT8M8M')]
        raw_event_data = auth_with_key[0]
        final_event = Event(date=raw_event_data[0], type=TYPES['AUTH_KEY'], username=raw_event_data[1],
                            user_ip=raw_event_data[2],
                            details=raw_event_data[3] + raw_event_data[4])
        return final_event
    failed_login = failed_login_re.findall(line)
    if failed_login:
        # [('Jul  3 19:58:30', 'warner', '192.168.1.6')]
        raw_event_data = failed_login[0]
        final_event = Event(date=raw_event_data[0], type=TYPES['AUTH_FAILED'], username=raw_event_data[1],
                            user_ip=raw_event_data[2],
                            details=None)
        return final_event
    sudo_command = sudo_command_re.findall(line)
    if sudo_command:
        # [('Jul  3 20:01:18', 'warner', '/usr/bin/apt-get update')]
        raw_event_data = sudo_command[0]
        final_event = Event(date=raw_event_data[0], type=TYPES['SUDO_COMMAND'], username=raw_event_data[1],
                            user_ip=None,
                            details=raw_event_data[2])
        return final_event
    return


if __name__ == '__main__':
    parser = create_parser()
    namespace = parser.parse_args()
    if DATABASE.get('db_type') == 'postgresql':
        db_connector = PostgresConnector
    else:
        db_connector = SqliteConnector
    DATABASE.pop('db_type')
    if not namespace.command:
        parser.print_help()
    elif namespace.command == 'parse':
        # Read and parse ssh logs
        ssh_logs = LogsFinderAndReader(logdir=LOG_SETTINGS['security_log_dir'],
                                       logname=LOG_SETTINGS['security_log_name'])
        saver = db_connector(db_settings=DATABASE)
        string_counter = 0
        for one_line in ssh_logs.get_lines():
            string_counter += 1
            e = get_event_from_string_auth(one_line)
            if e:
                saver.save(e)
        print('Parsed {} strings from system authorization logs'.format(string_counter))
        # Read and parse APT-History
        apt_logs = LogsFinderAndReader(logdir=LOG_SETTINGS['apt_log_dir'], logname=LOG_SETTINGS['apt_log_name'])
        """
        Log format
        Start-Date: 2016-04-07  19:25:28
        Commandline: apt-get install apt-transport-https ca-certificates fish
        Install: xsel:amd64 (1.2.0-2, automatic), fish:amd64 (2.0.0-1)
        End-Date: 2016-04-07  19:25:29
        """
        string_counter = 0
        start_date = None
        for one_line in apt_logs.get_lines():
            string_counter += 1
            if 'Start-Date:' in one_line:
                start_date = one_line.split(' ', maxsplit=1)[1]
                continue
            if 'End-Date:' in one_line:
                start_date = None
                continue
            if start_date:
                apt_get_commands = apt_get_commands_re.findall(one_line)
                if apt_get_commands:
                    raw_data = apt_get_commands[0]
                    e_type = TYPES['INSTALL_PACKAGE'] if raw_data[0] == 'install' else TYPES['REMOVE_PACKAGE']
                    e = Event(date=start_date, type=e_type, username='root', user_ip=None, details=raw_data[1])
                    saver.save(e)
        print('Parsed {} strings from apt history logs'.format(string_counter))
    elif namespace.command == 'show':
        # PARSER.SHOW
        reader = db_connector(db_settings=DATABASE)
        templates = {
            1: '[{_time}] User {e.username} logged using key from ip {e.user_ip}',
            2: '[{_time}] User {e.username} logged using password from ip {e.user_ip}',
            3: '\033[91m[{_time}] User {e.username} failed to login from ip {e.user_ip}\033[0m',  # red color
            4: '[{_time}] User {e.username} used `sudo` and executed: \033[92m{e.details}\033[0m',  # green color
            5: '[{_time}] Install packaged: \033[4m{e.details}\033[0m',  # underscore
            6: '[{_time}] Uninstall packages: {e.details}',
        }
        out_timezone = pytz.timezone(OUTPUT_TIMEZONE)
        print('\n{:-^80}'.format(''))
        print('{:^20}All times shown in {} timezone.'.format('', out_timezone.zone))
        if namespace.date:
            print('{:^20}All events since {}.'.format('', namespace.date))
        print('\n{:-^80}'.format(''))

        for event in reader.get_events(date_filter=namespace.date, timezone=out_timezone):
            our_event = Event(date=event[0], type=int(event[1]), username=event[2], user_ip=event[3], details=event[4])
            total_date = our_event.date.astimezone(out_timezone).strftime('%Y-%m-%d %H:%M:%S')
            templated_string = templates[our_event.type].format(_time=total_date, e=our_event)
            print('{:80}'.format(templated_string))
        print('\n{:-^80}'.format(''))
