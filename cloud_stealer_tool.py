#!/usr/bin/env python3
#    ___                      _
#   / __\   _ _ __ ___  _ __ | |_ ___  _ __ ___
#  / / | | | | '_ ` _ \| '_ \| __/ _ \| '_ ` _ \
# / /__| |_| | | | | | | |_) | || (_) | | | | | |
# \____/\__, |_| |_| |_| .__/ \__\___/|_| |_| |_|
#       |___/          |_|
#
# CYMPTOM LABS Copyright 2020. All rights reserved.
#
# Author: Yossi Nisani (yossi@cymptom.com) on 12/10/2021

import argparse
import logging
import sys
import time

from impacket import version
from impacket.examples import logger

from connection_class import Connection
from dpapi_class import Dpapi
from file_class import File
from registry_class import Registry
from static_methods import print_banner


def execute(user_options: argparse.Namespace):
    """
    Main function for execute
    :param user_options: User options base on the arguments
    :return:
    """
    res_dp = {}
    res_reg = []
    res_file = {}
    try:
        connection = Connection(username=user_options.user, password=user_options.password, domain=user_options.domain,
                                target=user_options.target)

        connection.connect()
    except Exception as e:
        if "STATUS_LOGON_FAILURE" in str(e):
            logging.error(
                f"Invalid Username or Password\nusername:{user_options.user}, password:{user_options.password}")
            sys.exit(1)
        else:
            logging.error(
                f"Failed to connect to {user_options.target} using {user_options.user},{user_options.password}")
            sys.exit(1)
    if user_options.all or (user_options.file == False and user_options.env == False and user_options.dpapi == False):
        res_dp = dpapi_execute(connection)
        res_reg = reg_execute(connection)
        res_file = execute_file(connection)
        print_res(res_dp, res_file, res_reg, target=user_options.target)
        return
    if user_options.file:
        res_file = execute_file(connection)
        print_res(res_dp, res_file, res_reg)
    if user_options.dpapi:
        res_dp = dpapi_execute(connection)
    if user_options.env:
        res_reg = reg_execute(connection)

    print_res(res_dp, res_file, res_reg, target=user_options.target)


def print_res(res_dp=None, res_file=None, res_reg=None, target=None):
    """
    Print the results
    :param res_dp:  result of dpapi function
    :param res_file: result of file function
    :param res_reg: result of registry function
    :param target: target
    :return:
    """
    logging.info("Printing result:\n")
    logging.getLogger().handlers[0].flush()
    if res_dp:
        logging.info(f"There are {len(res_dp)} users with DPAPI secrets that have access to Azure:\n")
        for k, v in res_dp.items():
            logging.info(f"Found in user: {k}\n")
            for k1, v1 in v.items():
                logging.info(f"{k1}: {v1}")
    if res_reg:
        logging.info(
            f"\nThe target {target} contains environment variables that contain access to Azure:\n")
        for i in res_reg:
            logging.info(i)
    if res_file:
        logging.info(f"\nFound .azure folder containing access Azure:\n")
        for k, v in res_file.items():
            logging.info(f"Path: {k}\n Token:{v}")

    if not res_dp and not res_file and not res_reg:
        logging.info(f"Target {target} does not contain Tokens/Passwords that allow access to Azure")


def execute_file(connection):
    """
    Function to execute a file service
    :param connection: Connection to the target
    :return:
    """
    logging.debug("Searching for Tokens in .azure folder:")
    file = File(connection)
    logging.debug(f"Finish file execution on target {connection.target}:")
    return file.search_for_azure_file()


def reg_execute(connection):
    """
    Function to execute a registry service
    :param connection: Connection to the target
    :return:
    """
    logging.debug(f"Searching in environment variable on target {connection.target} to access Azure:")
    reg = Registry(connection)
    logging.debug(f"Finish registry execution on target {connection.target}:")
    return reg.enum_values()


def dpapi_execute(connection):
    """
    Function to execute a dpapi service
    :param connection: Connection to the target
    :return:
    """
    logging.debug(f"Searching for DPAPI secret on target {connection.target} to access Azure:")
    dp = Dpapi(connection)
    logging.debug(f"Finish Dpapi execution on target {connection.target}:")
    return dp.execute()


if __name__ == "__main__":
    print_banner()
    sys.tracebacklimit = -1
    parser = argparse.ArgumentParser(add_help=True,
                                     description="Queries a specified computer and dump Azure credentials or "
                                                 "tokens.\nRequire administrative access to the machine ") 

    parser.add_argument('-t', '--target', action='store', help='target to query (IP or Hostname)', required=True)
    parser.add_argument('-u', '--user', action='store', metavar='username', help='username for authentication',
                        required=True)
    parser.add_argument('-p', '--password', action='store', help='password for authentication', required=True)
    parser.add_argument('-d', '--domain', action='store', default='', help='domain name')
    parser.add_argument('-e', '--env', action='store_true', help='search in environment variable')
    parser.add_argument('-D', '--dpapi', action='store_true', help='search in dpapi files')
    parser.add_argument('-f', '--file', action='store_true', help='search in .azure file')
    parser.add_argument('-a', '--all', action='store_true', help='search all methods')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    options = parser.parse_args()
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
    logger.init()
    logging.info(f"Searching for Azure token and password in target {options.target}")
    execute(options)
