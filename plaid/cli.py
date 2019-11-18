#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=C,R,W

import logging
from sys import stdout

import click
import traceback
import simplejson as json
from flask.cli import AppGroup
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists
from toolz.dicttoolz import get_in

# from superset import (
#     app, db, dict_import_export_util, security_manager, utils,
# )

group = AppGroup('plaid')

@group.command()
@click.option('--drop-existing', '-d', is_flag=True,
              help='Drop the database if it exists.')
@click.option('--uri', '-u',
              help='Provide a SQLAlchemy URI to the server where the database '
                   'will be provisioned. Default is database.postgres setting '
                   'found in plaid.conf.')
def init_db(drop_existing, uri):
    """Provisions an empty postgres database with a 'superset' role to manage it."""
    super_uri = ''
    
    if isinstance(uri, str):
        super_uri = uri
    else:
        conf_path = '/etc/plaid/plaid.conf'  # Path to the config file
        with open(conf_path, 'r') as conf_file:
            config = json.load(conf_file)
        super_uri = get_in(['database', 'postgres'], config)

    engine = create_engine(super_uri)
    logging.info('Opening connection with URI: {}'.format(super_uri))
    con = engine.connect()
    try:
        role_name = 'superset'
        role_pass = 'army creator instance printer'
        database_name = 'superset'
        schema = 'public'
    
        result = con.execute('SELECT rolname FROM pg_roles;')
        roles = []
        for r in result:
            roles.append(r[0])

        # Create role if it doesn't exist.
        if ('superset' not in roles):
            con.execute('CREATE USER "{0}" PASSWORD "{1}";'.format(role_name, role_pass))
            logging.info('Role "{}" created succesfully.'.format(role_name))

        if (drop_existing):
            # Creating/Dropping databases cannot happen within a transaction.
            # So, lets close any implicit transaction opened with a new connection.
            con.execute('commit')
            con.execute('DROP DATABASE IF EXISTS {}'.format(database_name))
            logging.info('Dropped existing database.')

        if (database_exists(super_uri[:super_uri.rindex('/')+1] + database_name)):
            logging.warning('Database already exists. Rerun command with -d flag to drop it.')
            logging.info('Continuing with role grants.')
        else:
            # Creating/Dropping databases cannot happen within a transaction.
            # So, lets close any implicit transaction opened with a new connection.
            con.execute('commit')
            con.execute('CREATE DATABASE {0} WITH ENCODING="UTF8";'.format(database_name))
            logging.info('Created new database successfully.')

        # Grants CREATE, CONNECT, and TEMPORARY. Does not grant access to table data.
        con.execute(
            'GRANT ALL PRIVILEGES ON '
            'DATABASE "{}" to {};'.format(database_name, role_name)
        )
        logging.info('Granted database privileges.')

        con.execute('GRANT ALL ON SCHEMA "{0}" TO "{1}";'.format(schema, role_name))
        logging.info('Granted schema privileges.')
        
        # Grants access to all *existing* tables and sequences within the database.
        con.execute(
            'GRANT ALL PRIVILEGES ON ALL TABLES '
            'IN SCHEMA {} TO {};'.format(schema, role_name)
        )
        con.execute(
            'GRANT ALL PRIVILEGES ON ALL SEQUENCES '
            'IN SCHEMA {} TO {};'.format(schema, role_name)
        )
        logging.info('Granted existing table and sequence privileges.')
        

        # Grants access to all *future* tables and sequences within the database.
        con.execute(
            'ALTER DEFAULT PRIVILEGES IN SCHEMA {} '.format(schema) +
            'GRANT ALL PRIVILEGES ON TABLES TO {};'.format(role_name)
        )
        con.execute(
            'ALTER DEFAULT PRIVILEGES IN SCHEMA {} '.format(schema) +
            'GRANT ALL PRIVILEGES ON SEQUENCES TO {};'.format(role_name)
        )
        logging.info('Granted future table and sequence privileges.')
        con.close()
    except:
        logging.error(traceback.print_exc())
        con.close()
