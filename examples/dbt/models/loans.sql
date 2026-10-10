-- rebuilt on every run, as dbt's table materialization does: a new table each time
select 1 as id, 100.00::numeric(12, 2) as amount, 'ann'::varchar(32) as owner_name
