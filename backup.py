#!/usr/bin/env python3

""" Note:
Use   gpg --symmetric backup.tar   to encrypt (creates backup.tar.gpg)
Use   gpg --decrypt backup.tar.gpg > data.tar   to decrypt
See   https://rclone.org/drive/   for rclone config and info
      run   rclone config   setup a google-cloud project to get client-id
      and client-secret
"""

# DONE : check/delete old intermediate files
# TODO : use yy-mm-dd in filenames and autoremove old files
# DONE : use logging (to file and stdout)
# TODO : check integrity (download, decrypt, unzip, compare hash of .tar file)
#        use tar's ability to check/validate the file
# TODO : strip common path in filenames inside tar

import sys
import os
import subprocess
import getpass
import shlex
import logging
import json
import datetime


def fix_path(path):
    return os.path.abspath(
        os.path.expanduser(
            os.path.expandvars(
                path)))


# if DRY_RUN is True it will print the commands generated but not execute them
DRY_RUN = False

SKIP_TAG = '.skip-backup'

EXCLUDES = [
    '*.log',
    '*.bak',
    '*.pyc',
    '.~lock*#',  # open libre office files
    '.git',
    'tmp',
    'venv',
    '.venv',
    'venv.*',
    '__pycache__',
    '.vs',
    '.wine',
    'Code/**/.nuget',
    'Code/**/bin',
    'Code/**/obj',
    'Code/**/build',
    'Code/**/*.o',
    'Code/**/*.dll',
]

SOURCES = list(
    map(fix_path, (
        '~/Documents/Schule/',
        '~/Documents/Privat/',
        '~/Documents/Code/',
        '~/Documents/Books/',
        '~/Documents/Musik/',
        '~/Documents/Studium/',
        '~/Documents/Theater/',
        '~/Documents/cubox.md',
        '~/Documents/linluk.kdbx',
        '~/Documents/vimium.json',
        '~/.irssi/',
        '~/.newsboat/',
        '~/.ssh/',
        '~/.todo/',
        '~/.config/nvim/',
        '~/.config/rclone/',
        '~/.bashrc.d/',
        '~/.bashrc',
        '~/.tmux.conf',
        '~/.profile',
        '~/RANDOM.md',
        '~/lukas-singer.eu/'
    )))

LOCAL_DESTINATION = fix_path('~/Backup/')

# WARN: cannot be used with shlex.quote()
#       --> make sure that Backup.remote_filename()
#           returns a propper quoted and working
#           remote path!
#           and that Backup.rclone_check_command()
#           also work as expected.
#           remote_filename() uses REMOTE_DESTINATION
#           to build the remote filename.
#           rclone_check_command() uses REMOTE_DESTINATION
#           directly to check if it exists.
REMOTE_DESTINATION = '"Google Drive Backup":backup/'

LOGFILE = os.path.join(LOCAL_DESTINATION, 'backup.log')
LOGLEVEL = logging.INFO


class Backup(object):
    def __init__(self):
        super().__init__()

    def sources(self) -> str:
        return ' '.join(f'{shlex.quote(source)}' for source in SOURCES)

    def tar_filename(self) -> str:
        # f"{datetime.datetime.now():%Y%m%d%H%M%S}.tar")  # .gz")
        return os.path.join(LOCAL_DESTINATION, 'backup.tar')

    def gzip_filename(self) -> str:
        return f'{self.tar_filename()}.gz'

    def gpg_filename(self) -> str:
        return f'{self.gzip_filename()}.gpg'

    def remote_filename(self) -> str:
        return os.path.join(REMOTE_DESTINATION,
                            f'{datetime.date.today():%Y%m%d}.tar.gz.gpg')

    def parse_filename(self, filename: str) -> tuple[int, int, int] | None:
        """ parse the date from a filename in the format of
            Backup.remote_filename() which is  YYYYMMDD.tar.gz.gpg """
        filename = os.path.basename(filename)
        ymd, *ext = filename.split('.')
        if ymd.isdigit() and len(ymd) == 8:
            return tuple(map(int, (ymd[0:4], ymd[4:6], ymd[6:8])))
        return None

    def excludes(self) -> str:
        return ' '.join(
            f'--exclude={shlex.quote(exclude)}' for exclude in EXCLUDES)

    def flags(self) -> str:
        return ' '.join([
            '--create',  # create new archive
            '--preserve-permissions',  # preserve rights
            '--exclude-vcs',  # ignore vcs-directories
            '--exclude-vcs-ignores',  # ignore files listed in ignore files
            '--exclude-caches',
            '--exclude-backups',
            f'--exclude-tag={shlex.quote(SKIP_TAG)}',
            '--recursion'
        ])

    def tar_command(self) -> str:
        return ' '.join([
                'tar',
                self.flags(),
                f'--file={shlex.quote(self.tar_filename())}',
                self.excludes(),
                self.sources()
        ])

    def gzip_command(self) -> str:
        # NOTE :
        # gzip doesn't allow for naming output files
        # it will create a file named like the input file
        # with .gz extension by default.
        # a workaround would be to output to STDOUT using '--stdout'
        # and redirecting it to a file.
        # but subprocess.run() wouldn't support it.
        # a workaround for that would be to redirect to use '--stdout'
        # and handling it here in python (pass it to a file descriptor)
        return ' '.join([
            'gzip',
            '--keep',
            '--best',
            # '--verbose',
            shlex.quote(self.tar_filename())
        ])

    def gpg_encrypt_command(self) -> str:
        return ' '.join([
            'gpg',
            '--symmetric',
            f'--output {shlex.quote(self.gpg_filename())}',
            '--passphrase-fd 0',  # read the passphrase from STDIN
            '--batch',
            '--pinentry-mode loopback',
            '--no-symkey-cache',
            shlex.quote(self.gzip_filename())
        ])

    def rclone_upload_command(self) -> str:
        return ' '.join([
            'rclone',
            'copyto',
            shlex.quote(self.gpg_filename()),
            self.remote_filename(),  # WARN: shlex.quote() will not work here!
            '--progress'
        ])

    def rclone_check_command(self) -> str:
        return ' '.join([
            'rclone',
            'lsd',
            REMOTE_DESTINATION
        ])

    def rclone_list_command(self) -> str:
        return ' '.join([
            'rclone',
            'lsjson',
            REMOTE_DESTINATION
        ])

    def cleanup_local(self,
                      logger: logging.Logger,
                      gpg: bool = True,
                      tar: bool = True,
                      gzip: bool = False) -> int:
        def _check_and_remove(filename: str) -> None:
            if gpg and os.path.isfile(filename):
                logger.info(f'Removing {filename}')
                os.remove(filename)

        if not DRY_RUN:
            logger.info('Local clean up')
            if gpg:
                _check_and_remove(self.gpg_filename())
            if tar:
                _check_and_remove(self.tar_filename())
            if gzip:
                _check_and_remove(self.gzip_filename())
        return 0

    def cleanup_remote(self, logger: logging.Logger) -> int:
        logger.warning('cleanup_remote() not yet implemented.')
        return 0
        # global DRY_RUN
        # DRY_RUN = False
        remote_info = dict()
        logger.info('Getting remote file list using rclone')
        if self.run(self.rclone_list_command(), logger, remote_info) != 0:
            logger.error('Abort!')
            return 1
        drive_list = json.loads(remote_info.get('stdout', b'[]'))
        for drive_entry in drive_list:
            print(drive_entry)
        # datetime.date.
        # DRY_RUN = True
        return 0

    def run(self,
            command: str,
            logger: logging.Logger,
            result: dict | None = None,
            **kwargs) -> int:
        if kwargs is None:
            kwargs = dict()
        kwargs.update({'shell': True, 'cwd': LOCAL_DESTINATION})
        if result is not None:
            kwargs.update({'stdout': subprocess.PIPE,
                           'stderr': subprocess.PIPE})
        safe_kwargs = kwargs.copy()
        # passphrase for gpg en-/decryption is stored in 'input'
        # so I don't want to print/log it
        if 'input' in safe_kwargs:
            safe_kwargs['input'] = '*' * len(safe_kwargs['input'])
        logger.info(f'Calling: {command}')
        logger.debug(f'Settings: {safe_kwargs}')
        if DRY_RUN:
            logger.debug('DRY RUN (not executing!)')
            if result is not None:
                result.update({'Returncode': 0,
                               'stdout': b'',
                               'stderr': b''})
            return 0
        ret = subprocess.run(command, **kwargs)
        if result is not None:
            result.update({'Returncode': ret.returncode,
                           'stdout': ret.stdout,
                           'stderr': ret.stderr})
        logger.info(f'Returncode: {ret.returncode}')
        return ret.returncode

    def backup(self, logger: logging.Logger) -> int:
        logger.info('Launching Backup ...')

        if DRY_RUN:
            passphrase = 'test'
            logger.debug('DRY RUN (not asking for passphrase)')
        else:
            passphrase = getpass.getpass('Passphrase > ')
            if passphrase != getpass.getpass('Repeat > '):
                logger.error("Passphrases doesn't match!")
                return 1
            elif passphrase == '':
                logger.error('Passphrase must not be empty!')
                return 2

        if self.cleanup_local(logger, True, True, True) != 0:
            logger.error('Abort!')
            return 3

        logger.info('Starting to archive using tar')
        if self.run(self.tar_command(), logger) != 0:
            logger.error('Abort!')
            return 4

        logger.info('Starting to compress using gzip')
        if self.run(self.gzip_command(), logger) != 0:
            logger.error('Abort!')
            return 5

        logger.info('Starting to encrypt using gpg')
        if self.run(self.gpg_encrypt_command(),
                    logger,
                    input=passphrase.encode(sys.stdin.encoding)) != 0:
            logger.error('Abort!')
            return 6

        logger.info('Checking remote destination using rclone')
        if self.run(self.rclone_check_command(), logger) != 0:
            logger.error('Abort!')
            return 7

        logger.info('Starting to upload using rclone')
        if self.run(self.rclone_upload_command(), logger) != 0:
            logger.error('Abort!')
            return 8

        if self.cleanup_remote(logger) != 0:
            logger.error('Abort!')
            return 9

        if self.cleanup_local(logger, True, True, False) != 0:
            logger.error('Abort!')
            return 10

        logger.info('Done!')
        return 0


if __name__ == '__main__':
    logger = logging.getLogger()
    logger.setLevel(logging.NOTSET)
    log_formatter = logging.Formatter(
        '[%(asctime)s][%(levelname)s] %(message)s')

    log_file_handler = logging.FileHandler(LOGFILE)
    log_file_handler.setFormatter(log_formatter)
    log_file_handler.setLevel(logging.INFO)
    logger.addHandler(log_file_handler)

    log_stdout_handler = logging.StreamHandler(sys.stdout)
    log_stdout_handler.setFormatter(log_formatter)
    log_stdout_handler.setLevel(logging.DEBUG)
    log_stdout_handler.addFilter(lambda r: r.levelno <= logging.WARNING)
    logger.addHandler(log_stdout_handler)

    log_stderr_handler = logging.StreamHandler(sys.stderr)
    log_stderr_handler.setFormatter(log_formatter)
    log_stderr_handler.setLevel(logging.ERROR)
    logger.addHandler(log_stderr_handler)

    logger.info(f'{sys.executable=}|{sys.version=}|{sys.path=}|{os.getcwd()=}')

    b = Backup()
    err = b.backup(logger)
    # print(b.parse_filename(b.remote_filename()))
    if err > 0:
        logger.critical(f'Backup failed with errorcode {err}.')
        quit(err)
