import mysql.connector
import json

with open("app/storage/secrets.json", "r") as f:
    secrets = json.load(f)

db = mysql.connector.connect(
    host=secrets["dbhost"],
    user=secrets["dbuser"],
    password=secrets["dbpass"],
)

cursor = db.cursor()
cursor.execute("CREATE DATABASE IF NOT EXISTS securechat")
db.close()