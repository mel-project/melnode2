-- Add migration script here
create table blocks(height integer primary key, header blob not null, block blob not null) strict;