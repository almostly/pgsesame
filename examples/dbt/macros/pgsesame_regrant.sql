{#
  Put back the grants pgsesame declares on the model just built.

  A rebuilt table is a new object, and its grants went with the old one. After an
  apply, `sesame grants spec.yaml --format csv` (loaded by publish_grants.py) fills
  monitoring.declared_grants with what the spec grants; this hook reads the rows
  for this model (its own, and its schema's *) and grants them, in the model's
  transaction. Grantees that don't exist are skipped; until the table exists,
  nothing happens. Turn it off with --vars '{pgsesame_regrant: false}'.
#}
{% macro pgsesame_regrant(declared='monitoring.declared_grants') %}
  {%- if not execute or not var('pgsesame_regrant', true) -%}{{ return('') }}{%- endif -%}
  {%- set schema, table = declared.split('.') -%}
  {%- set found = run_query(
      "select count(*) from pg_tables where schemaname = '" ~ schema
      ~ "' and tablename = '" ~ table ~ "'") -%}
  {%- if found.columns[0].values()[0] | int == 0 -%}{{ return('') }}{%- endif -%}
  {%- set rows = run_query(
      "select d.privilege, d.\"column\", d.grantee, d.grantee_type from " ~ declared ~ " d"
      ~ " where d.schema = '" ~ this.schema ~ "'"
      ~ " and d.object in ('" ~ this.identifier ~ "', '*')"
      ~ " and d.object_type in ('tables', 'views', 'columns')"
      ~ " and (d.object_type <> 'columns' or d.object = '" ~ this.identifier ~ "')"
      ~ " and case d.grantee_type"
      ~ "   when 'user' then exists (select 1 from pg_user u where u.usename = d.grantee)"
      ~ "   when 'group' then exists (select 1 from pg_catalog.pg_group where groname = d.grantee)"
      ~ "   when 'public' then true"
      ~ "   else exists (select 1 from svv_roles r where r.role_name = d.grantee) end"
      ~ " order by 3, 1, 2") -%}
  {%- set statements = [] -%}
  {%- for privilege, column, grantee, grantee_type in rows.rows -%}
    {%- set to = {'group': 'GROUP ', 'role': 'ROLE '}.get(grantee_type, '') -%}
    {%- set who = 'PUBLIC' if grantee_type == 'public' else adapter.quote(grantee) -%}
    {%- set cols = ' (' ~ adapter.quote(column) ~ ')' if column else '' -%}
    {%- do statements.append(
        'grant ' ~ privilege ~ cols ~ ' on ' ~ this ~ ' to ' ~ to ~ who) -%}
  {%- endfor -%}
  {{ return(statements | join(';\n')) }}
{% endmacro %}
