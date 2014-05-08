#!/usr/bin/python
import MySQLdb

db = MySQLdb.connect("localhost", "snowmanclient", "snowmanclient")
c = db.cursor()
c.execute("DROP DATABASE snowmanclient")
c.execute("CREATE DATABASE snowmanclient")
c.close()
db.close()
