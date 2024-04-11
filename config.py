import os

DEBUG = True
# TESTING = True
MYSQL_HOST = 'localhost'
MYSQL_USER = 'root'
MYSQL_PASSWORD = os.getenv('')
MYSQL_DB = 'tracker'
MYSQL_CURSORCLASS = 'DictCursor'
SECRET_KEY = 'abcd2123445'
MAIL_SERVER = 'smtp.googlemail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = os.environ.get('EMAIL_USER')
MAIL_PASSWORD = os.environ.get('EMAIL_PASS')