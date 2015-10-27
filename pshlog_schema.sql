drop table if exists entries;
create table pshlog(
  id integer primary key autoincrement,
  host text not null,
  attacker text,
  tstamp integer not null,
  artifact text not null  
);
