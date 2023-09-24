# (27017) Mongodb

<details>

<summary>Background Info</summary>

MongoDB is a document-oriented NoSQL database. In a document-oriented NoSQL database, data is organized into

* Databases
* Collections (tables in MySQL)
* Documents (rows in MySQL)
* Fields (columns in MySQL)

</details>

<details>

<summary>Boolean operators</summary>

* $and&#x20;
* $or
* $eq (equivalent to = in MySQL)

</details>

<details>

<summary>Commands</summary>

* show databases;

<!---->

* use <_database\_name_>;

<!---->

* show collections;

<!---->

* db <_collection\_name>_.find(); (to show fields)

</details>

<details>

<summary>Connect to Remote MongoDB</summary>

```bash
apt-geintt install mongodb-clients
mongo --host 192.168.192.110:27017
```

</details>



