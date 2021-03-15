CREATE SCHEMA IF NOT EXISTS openidconnect;


create table openid_connect_provider (
    id uuid not null,
    version int8 not null,
    date_created timestamp not null,
    last_updated timestamp not null,
    base_url varchar(255) not null,
    access_token_url varchar(255) not null,
    created_by varchar(255) not null,
    openid_connect_provider_type varchar(255) not null,
    label varchar(255) not null,
    primary key (id));


create table openid_connect_provider_parameters (
    openid_connect_provider_id uuid not null,
    parameters_object varchar(255),
    parameters_idx varchar(255),
    parameters_elt varchar(255) not null);

create index openidConnectProvider_created_by_idx on openid_connect_provider (created_by);
alter table if exists openid_connect_provider add constraint UK_hc3bjmsxauf094phcna8sdenr unique (label);

