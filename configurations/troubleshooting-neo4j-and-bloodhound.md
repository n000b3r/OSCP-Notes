# Troubleshooting Neo4j & BloodHound

### Problem

* Able to start `neo4j console` but [http://localhost:7474](http://localhost:7474) is unreachable

### Solution

[https://stackoverflow.com/questions/29487042/failed-connect-to-localhost7474-connection-refused-where-is-the-neo4j-server](https://stackoverflow.com/questions/29487042/failed-connect-to-localhost7474-connection-refused-where-is-the-neo4j-server)

Inside `/usr/share/neo4j/conf/neo4j.conf`:

```ini
dbms.default_listen_address=0.0.0.0
```
