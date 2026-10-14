-- Snowflake parse-rate corpus (tests/snowflake_corpus.rs). Public, legitimate SQL only.
-- Entries are separated by a line holding only `----`; each starts with a `-- source:` line.
-- Sources and licences (full texts in snowflake_corpus.LICENSES):
--   * dbt-labs/jaffle_shop @ fd7bfac (Apache-2.0): models rendered with stub macros, plus the dbt-snowflake materialization DDL around them: 10 statements
--   * get-select/dbt-snowflake-monitoring @ ff52462 (MIT): models rendered with stub macros, plus the dbt-snowflake materialization DDL around them: 57 statements
--   * statements dbt-snowflake sends (written for this corpus after the macros of dbt-labs/dbt-adapters @ 33ffe6a, dbt-snowflake, Apache-2.0): 46 statements
--   * tobymao/sqlglot @ b9c5f8d (MIT): the Snowflake statements of tests/dialects/test_snowflake.py (validate_identity / validate_all inputs; bare expressions dropped): 1052 statements
-- Rendering: {{ ref('m') }} -> ANALYTICS.DBT_PROD.m, {{ source('s','t') }} -> RAW.s.t, config/var/
-- dbt_utils macros stubbed; models whose macros could not be stubbed are left out.
----
-- source: dbt-labs/jaffle_shop models/customers.sql (compiled SELECT)
with customers as (

    select * from ANALYTICS.DBT_PROD.stg_customers

),

orders as (

    select * from ANALYTICS.DBT_PROD.stg_orders

),

payments as (

    select * from ANALYTICS.DBT_PROD.stg_payments

),

customer_orders as (

        select
        customer_id,

        min(order_date) as first_order,
        max(order_date) as most_recent_order,
        count(order_id) as number_of_orders
    from orders

    group by customer_id

),

customer_payments as (

    select
        orders.customer_id,
        sum(amount) as total_amount

    from payments

    left join orders on
         payments.order_id = orders.order_id

    group by orders.customer_id

),

final as (

    select
        customers.customer_id,
        customers.first_name,
        customers.last_name,
        customer_orders.first_order,
        customer_orders.most_recent_order,
        customer_orders.number_of_orders,
        customer_payments.total_amount as customer_lifetime_value

    from customers

    left join customer_orders
        on customers.customer_id = customer_orders.customer_id

    left join customer_payments
        on  customers.customer_id = customer_payments.customer_id

)

select * from final
----
-- source: dbt-labs/jaffle_shop models/customers.sql (view materialization)
create or replace   view ANALYTICS.DBT_PROD.customers



  as (
    with customers as (

    select * from ANALYTICS.DBT_PROD.stg_customers

),

orders as (

    select * from ANALYTICS.DBT_PROD.stg_orders

),

payments as (

    select * from ANALYTICS.DBT_PROD.stg_payments

),

customer_orders as (

        select
        customer_id,

        min(order_date) as first_order,
        max(order_date) as most_recent_order,
        count(order_id) as number_of_orders
    from orders

    group by customer_id

),

customer_payments as (

    select
        orders.customer_id,
        sum(amount) as total_amount

    from payments

    left join orders on
         payments.order_id = orders.order_id

    group by orders.customer_id

),

final as (

    select
        customers.customer_id,
        customers.first_name,
        customers.last_name,
        customer_orders.first_order,
        customer_orders.most_recent_order,
        customer_orders.number_of_orders,
        customer_payments.total_amount as customer_lifetime_value

    from customers

    left join customer_orders
        on customers.customer_id = customer_orders.customer_id

    left join customer_payments
        on  customers.customer_id = customer_payments.customer_id

)

select * from final
  )
----
-- source: dbt-labs/jaffle_shop models/orders.sql (compiled SELECT)
with orders as (

    select * from ANALYTICS.DBT_PROD.stg_orders

),

payments as (

    select * from ANALYTICS.DBT_PROD.stg_payments

),

order_payments as (

    select
        order_id,

        sum(case when payment_method = 'credit_card' then amount else 0 end) as credit_card_amount,
        sum(case when payment_method = 'coupon' then amount else 0 end) as coupon_amount,
        sum(case when payment_method = 'bank_transfer' then amount else 0 end) as bank_transfer_amount,
        sum(case when payment_method = 'gift_card' then amount else 0 end) as gift_card_amount,
        sum(amount) as total_amount

    from payments

    group by order_id

),

final as (

    select
        orders.order_id,
        orders.customer_id,
        orders.order_date,
        orders.status,

        order_payments.credit_card_amount,

        order_payments.coupon_amount,

        order_payments.bank_transfer_amount,

        order_payments.gift_card_amount,

        order_payments.total_amount as amount

    from orders


    left join order_payments
        on orders.order_id = order_payments.order_id

)

select * from final
----
-- source: dbt-labs/jaffle_shop models/orders.sql (view materialization)
create or replace   view ANALYTICS.DBT_PROD.orders



  as (
    with orders as (

    select * from ANALYTICS.DBT_PROD.stg_orders

),

payments as (

    select * from ANALYTICS.DBT_PROD.stg_payments

),

order_payments as (

    select
        order_id,

        sum(case when payment_method = 'credit_card' then amount else 0 end) as credit_card_amount,
        sum(case when payment_method = 'coupon' then amount else 0 end) as coupon_amount,
        sum(case when payment_method = 'bank_transfer' then amount else 0 end) as bank_transfer_amount,
        sum(case when payment_method = 'gift_card' then amount else 0 end) as gift_card_amount,
        sum(amount) as total_amount

    from payments

    group by order_id

),

final as (

    select
        orders.order_id,
        orders.customer_id,
        orders.order_date,
        orders.status,

        order_payments.credit_card_amount,

        order_payments.coupon_amount,

        order_payments.bank_transfer_amount,

        order_payments.gift_card_amount,

        order_payments.total_amount as amount

    from orders


    left join order_payments
        on orders.order_id = order_payments.order_id

)

select * from final
  )
----
-- source: dbt-labs/jaffle_shop models/staging/stg_customers.sql (compiled SELECT)
with source as (
    select * from ANALYTICS.DBT_PROD.raw_customers

),

renamed as (

    select
        id as customer_id,
        first_name,
        last_name

    from source

)

select * from renamed
----
-- source: dbt-labs/jaffle_shop models/staging/stg_customers.sql (view materialization)
create or replace   view ANALYTICS.DBT_PROD.stg_customers



  as (
    with source as (
    select * from ANALYTICS.DBT_PROD.raw_customers

),

renamed as (

    select
        id as customer_id,
        first_name,
        last_name

    from source

)

select * from renamed
  )
----
-- source: dbt-labs/jaffle_shop models/staging/stg_orders.sql (compiled SELECT)
with source as (
    select * from ANALYTICS.DBT_PROD.raw_orders

),

renamed as (

    select
        id as order_id,
        user_id as customer_id,
        order_date,
        status

    from source

)

select * from renamed
----
-- source: dbt-labs/jaffle_shop models/staging/stg_orders.sql (view materialization)
create or replace   view ANALYTICS.DBT_PROD.stg_orders



  as (
    with source as (
    select * from ANALYTICS.DBT_PROD.raw_orders

),

renamed as (

    select
        id as order_id,
        user_id as customer_id,
        order_date,
        status

    from source

)

select * from renamed
  )
----
-- source: dbt-labs/jaffle_shop models/staging/stg_payments.sql (compiled SELECT)
with source as (
    select * from ANALYTICS.DBT_PROD.raw_payments

),

renamed as (

    select
        id as payment_id,
        order_id,
        payment_method,

        -- `amount` is currently stored in cents, so we convert it to dollars
        amount / 100 as amount

    from source

)

select * from renamed
----
-- source: dbt-labs/jaffle_shop models/staging/stg_payments.sql (view materialization)
create or replace   view ANALYTICS.DBT_PROD.stg_payments



  as (
    with source as (
    select * from ANALYTICS.DBT_PROD.raw_payments

),

renamed as (

    select
        id as payment_id,
        order_id,
        payment_method,

        -- `amount` is currently stored in cents, so we convert it to dollars
        amount / 100 as amount

    from source

)

select * from renamed
  )
----
-- source: get-select/dbt-snowflake-monitoring models/cost_per_query.sql (compiled SELECT)
with
stop_threshold as (
    select max(end_time) as latest_ts
    from ANALYTICS.DBT_PROD.stg_warehouse_metering_history
),

filtered_queries as (
    select
        query_id,
        query_text as original_query_text,
        credits_used_cloud_services,
        warehouse_id,
        warehouse_size is not null as ran_on_warehouse,
        timeadd(
            'millisecond',
            queued_overload_time + compilation_time
            + queued_provisioning_time + queued_repair_time
            + list_external_files_time,
            start_time
        ) as execution_start_time,
        start_time,
        end_time,
        query_acceleration_bytes_scanned
    from ANALYTICS.DBT_PROD.stg_query_history
    where true
        and end_time <= (select stop_threshold.latest_ts from stop_threshold)

),

hours_list as (
    select
        dateadd(
            'hour',
            '-' || row_number() over (
order by seq4() asc),
            dateadd('day', '+1', current_date::timestamp_tz)
        ) as hour_start,
        dateadd('hour', '+1', hour_start) as hour_end


    from table(generator(rowcount => (24 * 1095)))

),

-- 1 row per hour a query ran
query_hours as (
    select
        hours_list.hour_start,
        hours_list.hour_end,
        queries.*
    from hours_list
    inner join filtered_queries as queries
        on hours_list.hour_start >= date_trunc('hour', queries.execution_start_time)
            and hours_list.hour_start < queries.end_time
            and queries.ran_on_warehouse
),

query_seconds_per_hour as (
    select
        *,
        datediff('millisecond', greatest(execution_start_time, hour_start), least(end_time, hour_end)) as num_milliseconds_query_ran,
        sum(num_milliseconds_query_ran) over (partition by warehouse_id, hour_start) as total_query_milliseconds_in_hour,
        div0(num_milliseconds_query_ran, total_query_milliseconds_in_hour) as fraction_of_total_query_time_in_hour,
        sum(query_acceleration_bytes_scanned) over (partition by warehouse_id, hour_start) as total_query_acceleration_bytes_scanned_in_hour,
        div0(query_acceleration_bytes_scanned, total_query_acceleration_bytes_scanned_in_hour) as fraction_of_total_query_acceleration_bytes_scanned_in_hour,
        hour_start as hour
    from query_hours
),

credits_billed_hourly as (
    select
        start_time as hour,
        entity_id as warehouse_id,
        sum(iff(service_type = 'WAREHOUSE_METERING', credits_used_compute, 0)) as credits_used_compute,
        sum(iff(service_type = 'WAREHOUSE_METERING', credits_used_cloud_services, 0)) as credits_used_cloud_services,
        sum(iff(service_type = 'QUERY_ACCELERATION', credits_used_compute, 0)) as credits_used_query_acceleration
    from ANALYTICS.DBT_PROD.stg_metering_history
    where true
        and service_type in ('QUERY_ACCELERATION', 'WAREHOUSE_METERING')
    group by 1, 2
),

query_cost as (
    select
        query_seconds_per_hour.*,
        credits_billed_hourly.credits_used_compute * query_seconds_per_hour.fraction_of_total_query_time_in_hour as allocated_compute_credits_in_hour,
        allocated_compute_credits_in_hour * daily_rates.effective_rate as allocated_compute_cost_in_hour,
        credits_billed_hourly.credits_used_query_acceleration * query_seconds_per_hour.fraction_of_total_query_acceleration_bytes_scanned_in_hour as allocated_query_acceleration_credits_in_hour,
        allocated_query_acceleration_credits_in_hour * daily_rates.effective_rate as allocated_query_acceleration_cost_in_hour
    from query_seconds_per_hour
    inner join credits_billed_hourly
        on query_seconds_per_hour.warehouse_id = credits_billed_hourly.warehouse_id
            and query_seconds_per_hour.hour = credits_billed_hourly.hour
    inner join ANALYTICS.DBT_PROD.daily_rates as daily_rates
        on date(query_seconds_per_hour.start_time) = daily_rates.date
            and daily_rates.service_type = 'WAREHOUSE_METERING'
            and daily_rates.usage_type = 'compute'
),

cost_per_query as (
    select
        query_id,
        any_value(start_time) as start_time,
        any_value(end_time) as end_time,
        any_value(execution_start_time) as execution_start_time,
        sum(allocated_compute_cost_in_hour) as compute_cost,
        sum(allocated_compute_credits_in_hour) as compute_credits,
        sum(allocated_query_acceleration_cost_in_hour) as query_acceleration_cost,
        sum(allocated_query_acceleration_credits_in_hour) as query_acceleration_credits,
        any_value(credits_used_cloud_services) as credits_used_cloud_services,
        any_value(ran_on_warehouse) as ran_on_warehouse
    from query_cost
    group by 1
),

credits_billed_daily as (
    select
        date(hour) as date,
        sum(credits_used_compute) as daily_credits_used_compute,
        sum(credits_used_cloud_services) as daily_credits_used_cloud_services,
        greatest(daily_credits_used_cloud_services - daily_credits_used_compute * 0.1, 0) as daily_billable_cloud_services
    from credits_billed_hourly
    group by 1
),

all_queries as (
    select
        query_id,
        start_time,
        end_time,
        execution_start_time,
        compute_cost,
        compute_credits,
        query_acceleration_cost,
        query_acceleration_credits,
        credits_used_cloud_services,
        ran_on_warehouse
    from cost_per_query

    union all

    select
        query_id,
        start_time,
        end_time,
        execution_start_time,
        0 as compute_cost,
        0 as compute_credits,
        0 as query_acceleration_cost,
        0 as query_acceleration_credits,
        credits_used_cloud_services,
        ran_on_warehouse
    from filtered_queries
    where
        not ran_on_warehouse
)

select
    all_queries.query_id,
    all_queries.start_time,
    all_queries.end_time,
    all_queries.execution_start_time,
    all_queries.compute_cost,
    all_queries.compute_credits,
    all_queries.query_acceleration_cost,
    all_queries.query_acceleration_credits,
    -- For the most recent day, which is not yet complete, this calculation won't be perfect.
    -- For example, at 12PM on the latest day, it's possible that cloud credits make up <10% of compute cost, so the queries
    -- from that day are not allocated any cloud_services_cost. The next time the model runs, after we have the full day of data,
    -- this may change if cloud credits make up >10% of compute cost.
    (div0(all_queries.credits_used_cloud_services, credits_billed_daily.daily_credits_used_cloud_services) * credits_billed_daily.daily_billable_cloud_services) * coalesce(daily_rates.effective_rate, current_rates.effective_rate) as cloud_services_cost,
    div0(all_queries.credits_used_cloud_services, credits_billed_daily.daily_credits_used_cloud_services) * credits_billed_daily.daily_billable_cloud_services as cloud_services_credits,
    all_queries.compute_cost + all_queries.query_acceleration_cost + cloud_services_cost as query_cost,
    all_queries.compute_credits + all_queries.query_acceleration_credits + cloud_services_credits as query_credits,
    all_queries.ran_on_warehouse,
    coalesce(daily_rates.currency, current_rates.currency) as currency
from all_queries
inner join credits_billed_daily
    on date(all_queries.start_time) = credits_billed_daily.date
left join ANALYTICS.DBT_PROD.daily_rates as daily_rates
    on date(all_queries.start_time) = daily_rates.date
        and daily_rates.service_type = 'CLOUD_SERVICES'
        and daily_rates.usage_type = 'cloud services'
inner join ANALYTICS.DBT_PROD.daily_rates as current_rates
    on current_rates.is_latest_rate
        and current_rates.service_type = 'CLOUD_SERVICES'
        and current_rates.usage_type = 'cloud services'
order by all_queries.start_time asc
----
-- source: get-select/dbt-snowflake-monitoring models/cost_per_query.sql (incremental temp view)
create or replace  temporary view ANALYTICS.DBT_PROD.cost_per_query__dbt_tmp
  as (
with
stop_threshold as (
    select max(end_time) as latest_ts
    from ANALYTICS.DBT_PROD.stg_warehouse_metering_history
),

filtered_queries as (
    select
        query_id,
        query_text as original_query_text,
        credits_used_cloud_services,
        warehouse_id,
        warehouse_size is not null as ran_on_warehouse,
        timeadd(
            'millisecond',
            queued_overload_time + compilation_time
            + queued_provisioning_time + queued_repair_time
            + list_external_files_time,
            start_time
        ) as execution_start_time,
        start_time,
        end_time,
        query_acceleration_bytes_scanned
    from ANALYTICS.DBT_PROD.stg_query_history
    where true
        and end_time <= (select stop_threshold.latest_ts from stop_threshold)

),

hours_list as (
    select
        dateadd(
            'hour',
            '-' || row_number() over (
order by seq4() asc),
            dateadd('day', '+1', current_date::timestamp_tz)
        ) as hour_start,
        dateadd('hour', '+1', hour_start) as hour_end


    from table(generator(rowcount => (24 * 1095)))

),

-- 1 row per hour a query ran
query_hours as (
    select
        hours_list.hour_start,
        hours_list.hour_end,
        queries.*
    from hours_list
    inner join filtered_queries as queries
        on hours_list.hour_start >= date_trunc('hour', queries.execution_start_time)
            and hours_list.hour_start < queries.end_time
            and queries.ran_on_warehouse
),

query_seconds_per_hour as (
    select
        *,
        datediff('millisecond', greatest(execution_start_time, hour_start), least(end_time, hour_end)) as num_milliseconds_query_ran,
        sum(num_milliseconds_query_ran) over (partition by warehouse_id, hour_start) as total_query_milliseconds_in_hour,
        div0(num_milliseconds_query_ran, total_query_milliseconds_in_hour) as fraction_of_total_query_time_in_hour,
        sum(query_acceleration_bytes_scanned) over (partition by warehouse_id, hour_start) as total_query_acceleration_bytes_scanned_in_hour,
        div0(query_acceleration_bytes_scanned, total_query_acceleration_bytes_scanned_in_hour) as fraction_of_total_query_acceleration_bytes_scanned_in_hour,
        hour_start as hour
    from query_hours
),

credits_billed_hourly as (
    select
        start_time as hour,
        entity_id as warehouse_id,
        sum(iff(service_type = 'WAREHOUSE_METERING', credits_used_compute, 0)) as credits_used_compute,
        sum(iff(service_type = 'WAREHOUSE_METERING', credits_used_cloud_services, 0)) as credits_used_cloud_services,
        sum(iff(service_type = 'QUERY_ACCELERATION', credits_used_compute, 0)) as credits_used_query_acceleration
    from ANALYTICS.DBT_PROD.stg_metering_history
    where true
        and service_type in ('QUERY_ACCELERATION', 'WAREHOUSE_METERING')
    group by 1, 2
),

query_cost as (
    select
        query_seconds_per_hour.*,
        credits_billed_hourly.credits_used_compute * query_seconds_per_hour.fraction_of_total_query_time_in_hour as allocated_compute_credits_in_hour,
        allocated_compute_credits_in_hour * daily_rates.effective_rate as allocated_compute_cost_in_hour,
        credits_billed_hourly.credits_used_query_acceleration * query_seconds_per_hour.fraction_of_total_query_acceleration_bytes_scanned_in_hour as allocated_query_acceleration_credits_in_hour,
        allocated_query_acceleration_credits_in_hour * daily_rates.effective_rate as allocated_query_acceleration_cost_in_hour
    from query_seconds_per_hour
    inner join credits_billed_hourly
        on query_seconds_per_hour.warehouse_id = credits_billed_hourly.warehouse_id
            and query_seconds_per_hour.hour = credits_billed_hourly.hour
    inner join ANALYTICS.DBT_PROD.daily_rates as daily_rates
        on date(query_seconds_per_hour.start_time) = daily_rates.date
            and daily_rates.service_type = 'WAREHOUSE_METERING'
            and daily_rates.usage_type = 'compute'
),

cost_per_query as (
    select
        query_id,
        any_value(start_time) as start_time,
        any_value(end_time) as end_time,
        any_value(execution_start_time) as execution_start_time,
        sum(allocated_compute_cost_in_hour) as compute_cost,
        sum(allocated_compute_credits_in_hour) as compute_credits,
        sum(allocated_query_acceleration_cost_in_hour) as query_acceleration_cost,
        sum(allocated_query_acceleration_credits_in_hour) as query_acceleration_credits,
        any_value(credits_used_cloud_services) as credits_used_cloud_services,
        any_value(ran_on_warehouse) as ran_on_warehouse
    from query_cost
    group by 1
),

credits_billed_daily as (
    select
        date(hour) as date,
        sum(credits_used_compute) as daily_credits_used_compute,
        sum(credits_used_cloud_services) as daily_credits_used_cloud_services,
        greatest(daily_credits_used_cloud_services - daily_credits_used_compute * 0.1, 0) as daily_billable_cloud_services
    from credits_billed_hourly
    group by 1
),

all_queries as (
    select
        query_id,
        start_time,
        end_time,
        execution_start_time,
        compute_cost,
        compute_credits,
        query_acceleration_cost,
        query_acceleration_credits,
        credits_used_cloud_services,
        ran_on_warehouse
    from cost_per_query

    union all

    select
        query_id,
        start_time,
        end_time,
        execution_start_time,
        0 as compute_cost,
        0 as compute_credits,
        0 as query_acceleration_cost,
        0 as query_acceleration_credits,
        credits_used_cloud_services,
        ran_on_warehouse
    from filtered_queries
    where
        not ran_on_warehouse
)

select
    all_queries.query_id,
    all_queries.start_time,
    all_queries.end_time,
    all_queries.execution_start_time,
    all_queries.compute_cost,
    all_queries.compute_credits,
    all_queries.query_acceleration_cost,
    all_queries.query_acceleration_credits,
    -- For the most recent day, which is not yet complete, this calculation won't be perfect.
    -- For example, at 12PM on the latest day, it's possible that cloud credits make up <10% of compute cost, so the queries
    -- from that day are not allocated any cloud_services_cost. The next time the model runs, after we have the full day of data,
    -- this may change if cloud credits make up >10% of compute cost.
    (div0(all_queries.credits_used_cloud_services, credits_billed_daily.daily_credits_used_cloud_services) * credits_billed_daily.daily_billable_cloud_services) * coalesce(daily_rates.effective_rate, current_rates.effective_rate) as cloud_services_cost,
    div0(all_queries.credits_used_cloud_services, credits_billed_daily.daily_credits_used_cloud_services) * credits_billed_daily.daily_billable_cloud_services as cloud_services_credits,
    all_queries.compute_cost + all_queries.query_acceleration_cost + cloud_services_cost as query_cost,
    all_queries.compute_credits + all_queries.query_acceleration_credits + cloud_services_credits as query_credits,
    all_queries.ran_on_warehouse,
    coalesce(daily_rates.currency, current_rates.currency) as currency
from all_queries
inner join credits_billed_daily
    on date(all_queries.start_time) = credits_billed_daily.date
left join ANALYTICS.DBT_PROD.daily_rates as daily_rates
    on date(all_queries.start_time) = daily_rates.date
        and daily_rates.service_type = 'CLOUD_SERVICES'
        and daily_rates.usage_type = 'cloud services'
inner join ANALYTICS.DBT_PROD.daily_rates as current_rates
    on current_rates.is_latest_rate
        and current_rates.service_type = 'CLOUD_SERVICES'
        and current_rates.usage_type = 'cloud services'
order by all_queries.start_time asc
  )
----
-- source: get-select/dbt-snowflake-monitoring models/cost_per_query.sql (incremental merge)
merge into ANALYTICS.DBT_PROD.cost_per_query as DBT_INTERNAL_DEST
        using ANALYTICS.DBT_PROD.cost_per_query__dbt_tmp as DBT_INTERNAL_SOURCE
        on (
                DBT_INTERNAL_SOURCE.id = DBT_INTERNAL_DEST.id
            )
    when matched then update set
        "ID" = DBT_INTERNAL_SOURCE."ID"
    when not matched then insert
        ("ID")
    values
        ("ID")
----
-- source: get-select/dbt-snowflake-monitoring models/daily_rates.sql (compiled SELECT)
/*
snowflake.organization_usage.rate_sheet_daily isn't guaranteed to have 1 row per day per usage type.

If you don't consume any compute resources on a given day, there won't be a record.

This model guarantees 1 row per day per usage type, by filling in missing values with rates from the last
known day.
*/

with
dates_base as (
    select date_day as date from (
        select dateadd(day, seq4(), '2018-01-01') as date_day from table(generator(rowcount => 10000)) qualify date_day < dateadd(day, 1, current_date)
    )
),

rate_sheet_daily_base as (
    select
        date,
        usage_type,
        currency,
        effective_rate,
        service_type
    from ANALYTICS.DBT_PROD.stg_rate_sheet_daily
    where
        account_name = 'x'
),

stop_thresholds as (
    select min(date) as start_date
    from rate_sheet_daily_base

    union all

    select min(date) as start_date
    from ANALYTICS.DBT_PROD.remaining_balance_daily_without_contract_view
),

date_range as (
    select
        max(start_date) as start_date,
        current_date as end_date
    from stop_thresholds
),

remaining_balance_daily as (
    select
        date,
        free_usage_balance + capacity_balance + on_demand_consumption_balance + rollover_balance as remaining_balance,
        remaining_balance < 0 as is_account_in_overage
    from ANALYTICS.DBT_PROD.remaining_balance_daily_without_contract_view
),

latest_remaining_balance_daily as (
    select
        date,
        remaining_balance,
        is_account_in_overage
    from remaining_balance_daily
    qualify row_number() over (
order by date desc) = 1
),

rate_sheet_daily as (
    select rate_sheet_daily_base.*
    from rate_sheet_daily_base
    inner join date_range
        on rate_sheet_daily_base.date between date_range.start_date and date_range.end_date
),

rates_date_range_w_usage_types as (
    select
        date_range.start_date,
        date_range.end_date,
        usage_types.usage_type
    from date_range
    cross join (select distinct rate_sheet_daily.usage_type from rate_sheet_daily) as usage_types
),

base as (
    select
        db.date,
        dr.usage_type
    from dates_base as db
    inner join rates_date_range_w_usage_types as dr
        on db.date between dr.start_date and dr.end_date
),

rates_w_overage as (
    select
        base.date,
        base.usage_type,
        coalesce(
            rate_sheet_daily.service_type,
            lag(rate_sheet_daily.service_type) ignore nulls over (partition by base.usage_type
order by base.date),
            lead(rate_sheet_daily.service_type) ignore nulls over (partition by base.usage_type
order by base.date)
        ) as service_type,
        coalesce(
            rate_sheet_daily.effective_rate,
            lag(rate_sheet_daily.effective_rate) ignore nulls over (partition by base.usage_type
order by base.date),
            lead(rate_sheet_daily.effective_rate) ignore nulls over (partition by base.usage_type
order by base.date)
        ) as effective_rate,
        coalesce(
            rate_sheet_daily.currency,
            lag(rate_sheet_daily.currency) ignore nulls over (partition by base.usage_type
order by base.date),
            lead(rate_sheet_daily.currency) ignore nulls over (partition by base.usage_type
order by base.date)
        ) as currency,
        base.usage_type like 'overage-%' as is_overage_rate,
        replace(base.usage_type, 'overage-', '') as associated_usage_type,
        coalesce(remaining_balance_daily.is_account_in_overage, latest_remaining_balance_daily.is_account_in_overage, false) as _is_account_in_overage,
        case
            when _is_account_in_overage and is_overage_rate then 1
            when not _is_account_in_overage and not is_overage_rate then 1
            else 0
        end as rate_priority

    from base
    left join latest_remaining_balance_daily on latest_remaining_balance_daily.date is not null
    left join remaining_balance_daily
        on base.date = remaining_balance_daily.date
    left join rate_sheet_daily
        on base.date = rate_sheet_daily.date
            and base.usage_type = rate_sheet_daily.usage_type
),

rates as (
    select
        date,
        usage_type,
        associated_usage_type,
        service_type,
        effective_rate,
        currency,
        is_overage_rate
    from rates_w_overage
    qualify row_number() over (partition by date, service_type, associated_usage_type
order by rate_priority desc) = 1
)

select
    date,
    associated_usage_type as usage_type,
    service_type,
    effective_rate,
    currency,
    is_overage_rate,
    row_number() over (partition by service_type, associated_usage_type
order by date desc) = 1 as is_latest_rate
from rates
order by date
----
-- source: get-select/dbt-snowflake-monitoring models/daily_rates.sql (table materialization)
create or replace transient table ANALYTICS.DBT_PROD.daily_rates
    as
    (
/*
snowflake.organization_usage.rate_sheet_daily isn't guaranteed to have 1 row per day per usage type.

If you don't consume any compute resources on a given day, there won't be a record.

This model guarantees 1 row per day per usage type, by filling in missing values with rates from the last
known day.
*/

with
dates_base as (
    select date_day as date from (
        select dateadd(day, seq4(), '2018-01-01') as date_day from table(generator(rowcount => 10000)) qualify date_day < dateadd(day, 1, current_date)
    )
),

rate_sheet_daily_base as (
    select
        date,
        usage_type,
        currency,
        effective_rate,
        service_type
    from ANALYTICS.DBT_PROD.stg_rate_sheet_daily
    where
        account_name = 'x'
),

stop_thresholds as (
    select min(date) as start_date
    from rate_sheet_daily_base

    union all

    select min(date) as start_date
    from ANALYTICS.DBT_PROD.remaining_balance_daily_without_contract_view
),

date_range as (
    select
        max(start_date) as start_date,
        current_date as end_date
    from stop_thresholds
),

remaining_balance_daily as (
    select
        date,
        free_usage_balance + capacity_balance + on_demand_consumption_balance + rollover_balance as remaining_balance,
        remaining_balance < 0 as is_account_in_overage
    from ANALYTICS.DBT_PROD.remaining_balance_daily_without_contract_view
),

latest_remaining_balance_daily as (
    select
        date,
        remaining_balance,
        is_account_in_overage
    from remaining_balance_daily
    qualify row_number() over (
order by date desc) = 1
),

rate_sheet_daily as (
    select rate_sheet_daily_base.*
    from rate_sheet_daily_base
    inner join date_range
        on rate_sheet_daily_base.date between date_range.start_date and date_range.end_date
),

rates_date_range_w_usage_types as (
    select
        date_range.start_date,
        date_range.end_date,
        usage_types.usage_type
    from date_range
    cross join (select distinct rate_sheet_daily.usage_type from rate_sheet_daily) as usage_types
),

base as (
    select
        db.date,
        dr.usage_type
    from dates_base as db
    inner join rates_date_range_w_usage_types as dr
        on db.date between dr.start_date and dr.end_date
),

rates_w_overage as (
    select
        base.date,
        base.usage_type,
        coalesce(
            rate_sheet_daily.service_type,
            lag(rate_sheet_daily.service_type) ignore nulls over (partition by base.usage_type
order by base.date),
            lead(rate_sheet_daily.service_type) ignore nulls over (partition by base.usage_type
order by base.date)
        ) as service_type,
        coalesce(
            rate_sheet_daily.effective_rate,
            lag(rate_sheet_daily.effective_rate) ignore nulls over (partition by base.usage_type
order by base.date),
            lead(rate_sheet_daily.effective_rate) ignore nulls over (partition by base.usage_type
order by base.date)
        ) as effective_rate,
        coalesce(
            rate_sheet_daily.currency,
            lag(rate_sheet_daily.currency) ignore nulls over (partition by base.usage_type
order by base.date),
            lead(rate_sheet_daily.currency) ignore nulls over (partition by base.usage_type
order by base.date)
        ) as currency,
        base.usage_type like 'overage-%' as is_overage_rate,
        replace(base.usage_type, 'overage-', '') as associated_usage_type,
        coalesce(remaining_balance_daily.is_account_in_overage, latest_remaining_balance_daily.is_account_in_overage, false) as _is_account_in_overage,
        case
            when _is_account_in_overage and is_overage_rate then 1
            when not _is_account_in_overage and not is_overage_rate then 1
            else 0
        end as rate_priority

    from base
    left join latest_remaining_balance_daily on latest_remaining_balance_daily.date is not null
    left join remaining_balance_daily
        on base.date = remaining_balance_daily.date
    left join rate_sheet_daily
        on base.date = rate_sheet_daily.date
            and base.usage_type = rate_sheet_daily.usage_type
),

rates as (
    select
        date,
        usage_type,
        associated_usage_type,
        service_type,
        effective_rate,
        currency,
        is_overage_rate
    from rates_w_overage
    qualify row_number() over (partition by date, service_type, associated_usage_type
order by rate_priority desc) = 1
)

select
    date,
    associated_usage_type as usage_type,
    service_type,
    effective_rate,
    currency,
    is_overage_rate,
    row_number() over (partition by service_type, associated_usage_type
order by date desc) = 1 as is_latest_rate
from rates
order by date
    )
----
-- source: get-select/dbt-snowflake-monitoring models/daily_spend.sql (compiled SELECT)
select
    convert_timezone('UTC', hour)::date as date, -- get UTC date to align with Snowflake billing
    service,
    storage_type,
    warehouse_name,
    database_name,
    sum(usage) as usage,
    sum(usage_net_cloud_services) as usage_net_cloud_services,
    sum(spend) as spend,
    sum(spend_net_cloud_services) as spend_net_cloud_services,
    any_value(currency) as currency,
    any_value(usage_unit) as usage_unit,
    -- Weighted average rates across the day. Typically rates are consistent
    -- throughout a day so this should still be fairly accurate.
    case
        when sum(usage) > 0 then sum(spend) / sum(usage)
        when sum(usage_net_cloud_services) > 0 then sum(spend_net_cloud_services) / sum(usage_net_cloud_services)
        else 0
    end as usage_rate
from ANALYTICS.DBT_PROD.hourly_spend
group by 1, 2, 3, 4, 5
----
-- source: get-select/dbt-snowflake-monitoring models/daily_spend.sql (view materialization)
create or replace   view ANALYTICS.DBT_PROD.daily_spend



  as (
    select
    convert_timezone('UTC', hour)::date as date, -- get UTC date to align with Snowflake billing
    service,
    storage_type,
    warehouse_name,
    database_name,
    sum(usage) as usage,
    sum(usage_net_cloud_services) as usage_net_cloud_services,
    sum(spend) as spend,
    sum(spend_net_cloud_services) as spend_net_cloud_services,
    any_value(currency) as currency,
    any_value(usage_unit) as usage_unit,
    -- Weighted average rates across the day. Typically rates are consistent
    -- throughout a day so this should still be fairly accurate.
    case
        when sum(usage) > 0 then sum(spend) / sum(usage)
        when sum(usage_net_cloud_services) > 0 then sum(spend_net_cloud_services) / sum(usage_net_cloud_services)
        else 0
    end as usage_rate
from ANALYTICS.DBT_PROD.hourly_spend
group by 1, 2, 3, 4, 5
  )
----
-- source: get-select/dbt-snowflake-monitoring models/dbt_queries.sql (compiled SELECT)
select
    coalesce(
        dbt_metadata['dbt_query_tags_version']::string,
        dbt_metadata['dbt_snowflake_query_tags_version']::string
    ) as dbt_snowflake_query_tags_version, -- this will be null where the metadata came from a query comment in dbt-snowflake-monitoring versions <2.0.0
    dbt_metadata['invocation_id']::string as dbt_invocation_id,
    dbt_metadata['node_id']::string as dbt_node_id,
    dbt_metadata['node_resource_type']::string as dbt_node_resource_type,
    coalesce(dbt_metadata['node_name']::string, replace(array_slice(split(dbt_node_id, '.'), -1, array_size(split(dbt_node_id, '.')))[0], '"')) as dbt_node_name, -- we can just use node_name once enough time has been that users have migrated to v2.0.0
    dbt_metadata['materialized']::string as dbt_node_materialized,
    dbt_metadata['is_incremental']::boolean as dbt_node_is_incremental,
    dbt_metadata['node_alias']::string as dbt_node_alias,
    dbt_metadata['node_meta']::variant as dbt_node_meta,
    dbt_metadata['node_tags']::array as node_tags,
    iff(dbt_snowflake_query_tags_version >= '1.1.3', dbt_metadata['node_refs']::array, []) as dbt_node_refs, -- correct refs available from 1.1.3 onwards
    dbt_metadata['node_database']::string as dbt_node_database,
    dbt_metadata['node_schema']::string as dbt_node_schema,
    dbt_metadata['dbt_version']::string as dbt_version,
    dbt_metadata['project_name']::string as dbt_project_name,
    dbt_metadata['target_name']::string as dbt_target_name,
    dbt_metadata['target_database']::string as dbt_target_database,
    dbt_metadata['target_schema']::string as dbt_target_schema,
    dbt_metadata['node_package_name']::string as dbt_node_package_name,
    dbt_metadata['node_original_file_path']::string as dbt_node_original_file_path,
    dbt_metadata['dbt_cloud_project_id']::string as dbt_cloud_project_id,
    dbt_metadata['dbt_cloud_job_id']::string as dbt_cloud_job_id,
    dbt_metadata['dbt_cloud_run_id']::string as dbt_cloud_run_id,
    dbt_metadata['dbt_cloud_run_reason_category']::string as dbt_cloud_run_reason_category,
    dbt_metadata['dbt_cloud_run_reason']::string as dbt_cloud_run_reason,
    case
        when dbt_cloud_project_id is not null
        then
            'https://cloud.getdbt.com/deploy/' || 'x' || '/projects/' || dbt_cloud_project_id || '/jobs/' || dbt_cloud_job_id
    end as dbt_cloud_job_url,
    case
        when dbt_cloud_project_id is not null
        then
            'https://cloud.getdbt.com/deploy/' || 'x' || '/projects/' || dbt_cloud_project_id || '/runs/' || dbt_cloud_run_id
    end as dbt_cloud_run_url,
    * exclude dbt_metadata
from ANALYTICS.DBT_PROD.query_history_enriched
where dbt_metadata is not null
----
-- source: get-select/dbt-snowflake-monitoring models/dbt_queries.sql (incremental temp view)
create or replace  temporary view ANALYTICS.DBT_PROD.dbt_queries__dbt_tmp
  as (
select
    coalesce(
        dbt_metadata['dbt_query_tags_version']::string,
        dbt_metadata['dbt_snowflake_query_tags_version']::string
    ) as dbt_snowflake_query_tags_version, -- this will be null where the metadata came from a query comment in dbt-snowflake-monitoring versions <2.0.0
    dbt_metadata['invocation_id']::string as dbt_invocation_id,
    dbt_metadata['node_id']::string as dbt_node_id,
    dbt_metadata['node_resource_type']::string as dbt_node_resource_type,
    coalesce(dbt_metadata['node_name']::string, replace(array_slice(split(dbt_node_id, '.'), -1, array_size(split(dbt_node_id, '.')))[0], '"')) as dbt_node_name, -- we can just use node_name once enough time has been that users have migrated to v2.0.0
    dbt_metadata['materialized']::string as dbt_node_materialized,
    dbt_metadata['is_incremental']::boolean as dbt_node_is_incremental,
    dbt_metadata['node_alias']::string as dbt_node_alias,
    dbt_metadata['node_meta']::variant as dbt_node_meta,
    dbt_metadata['node_tags']::array as node_tags,
    iff(dbt_snowflake_query_tags_version >= '1.1.3', dbt_metadata['node_refs']::array, []) as dbt_node_refs, -- correct refs available from 1.1.3 onwards
    dbt_metadata['node_database']::string as dbt_node_database,
    dbt_metadata['node_schema']::string as dbt_node_schema,
    dbt_metadata['dbt_version']::string as dbt_version,
    dbt_metadata['project_name']::string as dbt_project_name,
    dbt_metadata['target_name']::string as dbt_target_name,
    dbt_metadata['target_database']::string as dbt_target_database,
    dbt_metadata['target_schema']::string as dbt_target_schema,
    dbt_metadata['node_package_name']::string as dbt_node_package_name,
    dbt_metadata['node_original_file_path']::string as dbt_node_original_file_path,
    dbt_metadata['dbt_cloud_project_id']::string as dbt_cloud_project_id,
    dbt_metadata['dbt_cloud_job_id']::string as dbt_cloud_job_id,
    dbt_metadata['dbt_cloud_run_id']::string as dbt_cloud_run_id,
    dbt_metadata['dbt_cloud_run_reason_category']::string as dbt_cloud_run_reason_category,
    dbt_metadata['dbt_cloud_run_reason']::string as dbt_cloud_run_reason,
    case
        when dbt_cloud_project_id is not null
        then
            'https://cloud.getdbt.com/deploy/' || 'x' || '/projects/' || dbt_cloud_project_id || '/jobs/' || dbt_cloud_job_id
    end as dbt_cloud_job_url,
    case
        when dbt_cloud_project_id is not null
        then
            'https://cloud.getdbt.com/deploy/' || 'x' || '/projects/' || dbt_cloud_project_id || '/runs/' || dbt_cloud_run_id
    end as dbt_cloud_run_url,
    * exclude dbt_metadata
from ANALYTICS.DBT_PROD.query_history_enriched
where dbt_metadata is not null
  )
----
-- source: get-select/dbt-snowflake-monitoring models/dbt_queries.sql (incremental merge)
merge into ANALYTICS.DBT_PROD.dbt_queries as DBT_INTERNAL_DEST
        using ANALYTICS.DBT_PROD.dbt_queries__dbt_tmp as DBT_INTERNAL_SOURCE
        on (
                DBT_INTERNAL_SOURCE.id = DBT_INTERNAL_DEST.id
            )
    when matched then update set
        "ID" = DBT_INTERNAL_SOURCE."ID"
    when not matched then insert
        ("ID")
    values
        ("ID")
----
-- source: get-select/dbt-snowflake-monitoring models/query_base_object_access.sql (compiled SELECT)
with
access_history as (
    select *
    from ANALYTICS.DBT_PROD.stg_access_history



),

access_history_flattened as (
    select
        access_history.query_id,
        access_history.query_start_time,
        access_history.user_name,
        objects_accessed.value:objectId::integer as table_id, -- will be null for secured views or tables from a data share
        objects_accessed.value:objectName::text as object_name,
        objects_accessed.value:objectDomain::text as object_domain,
        objects_accessed.value:columns as columns_array

    from access_history, lateral flatten(access_history.base_objects_accessed) as objects_accessed
),

access_history_flattened_w_columns as (
    select
        access_history_flattened.query_id,
        access_history_flattened.query_start_time,
        access_history_flattened.user_name,
        access_history_flattened.table_id,
        access_history_flattened.object_name,
        access_history_flattened.object_domain,
        array_agg(distinct columns.value:columnName::text) as columns_accessed
    from access_history_flattened, lateral flatten(access_history_flattened.columns_array) as columns
    where
        access_history_flattened.object_name is not null
    group by 1, 2, 3, 4, 5, 6
)

select
    md5(concat(query_id, object_name)) as _unique_id,
    *
from access_history_flattened_w_columns
order by query_start_time asc
----
-- source: get-select/dbt-snowflake-monitoring models/query_base_object_access.sql (incremental temp view)
create or replace  temporary view ANALYTICS.DBT_PROD.query_base_object_access__dbt_tmp
  as (
with
access_history as (
    select *
    from ANALYTICS.DBT_PROD.stg_access_history



),

access_history_flattened as (
    select
        access_history.query_id,
        access_history.query_start_time,
        access_history.user_name,
        objects_accessed.value:objectId::integer as table_id, -- will be null for secured views or tables from a data share
        objects_accessed.value:objectName::text as object_name,
        objects_accessed.value:objectDomain::text as object_domain,
        objects_accessed.value:columns as columns_array

    from access_history, lateral flatten(access_history.base_objects_accessed) as objects_accessed
),

access_history_flattened_w_columns as (
    select
        access_history_flattened.query_id,
        access_history_flattened.query_start_time,
        access_history_flattened.user_name,
        access_history_flattened.table_id,
        access_history_flattened.object_name,
        access_history_flattened.object_domain,
        array_agg(distinct columns.value:columnName::text) as columns_accessed
    from access_history_flattened, lateral flatten(access_history_flattened.columns_array) as columns
    where
        access_history_flattened.object_name is not null
    group by 1, 2, 3, 4, 5, 6
)

select
    md5(concat(query_id, object_name)) as _unique_id,
    *
from access_history_flattened_w_columns
order by query_start_time asc
  )
----
-- source: get-select/dbt-snowflake-monitoring models/query_base_object_access.sql (incremental merge)
merge into ANALYTICS.DBT_PROD.query_base_object_access as DBT_INTERNAL_DEST
        using ANALYTICS.DBT_PROD.query_base_object_access__dbt_tmp as DBT_INTERNAL_SOURCE
        on (
                DBT_INTERNAL_SOURCE.id = DBT_INTERNAL_DEST.id
            )
    when matched then update set
        "ID" = DBT_INTERNAL_SOURCE."ID"
    when not matched then insert
        ("ID")
    values
        ("ID")
----
-- source: get-select/dbt-snowflake-monitoring models/query_base_table_access.sql (compiled SELECT)
select
    _unique_id,
    query_id,
    query_start_time,
    user_name,
    object_name as full_table_name,
    table_id,
    columns_accessed
from ANALYTICS.DBT_PROD.query_base_object_access
where
    object_domain = 'Table' -- removes secured views
    and table_id is not null -- removes tables from a data share
----
-- source: get-select/dbt-snowflake-monitoring models/query_base_table_access.sql (view materialization)
create or replace   view ANALYTICS.DBT_PROD.query_base_table_access



  as (
    select
    _unique_id,
    query_id,
    query_start_time,
    user_name,
    object_name as full_table_name,
    table_id,
    columns_accessed
from ANALYTICS.DBT_PROD.query_base_object_access
where
    object_domain = 'Table' -- removes secured views
    and table_id is not null -- removes tables from a data share
  )
----
-- source: get-select/dbt-snowflake-monitoring models/query_direct_object_access.sql (compiled SELECT)
with
    access_history as (
        select *
        from ANALYTICS.DBT_PROD.stg_access_history



    ),

    access_history_flattened as (
        select
            access_history.query_id,
            access_history.query_start_time,
            access_history.user_name,
            objects_accessed.value:"objectId"::integer as table_id,  -- will be null for secured views or tables from a data share
            objects_accessed.value:"objectName"::text as object_name,
            objects_accessed.value:"objectDomain"::text as object_domain,
            objects_accessed.value:columns as columns_array

        from
            access_history,
            lateral flatten(access_history.direct_objects_accessed) as objects_accessed
    ),

    access_history_flattened_w_columns as (
        select
            access_history_flattened.query_id,
            access_history_flattened.query_start_time,
            access_history_flattened.user_name,
            access_history_flattened.table_id,
            access_history_flattened.object_name,
            access_history_flattened.object_domain,
            array_agg(distinct columns.value:"columnName"::text) as columns_accessed
        from
            access_history_flattened,
            lateral flatten(access_history_flattened.columns_array) as columns
        where access_history_flattened.object_name is not null
        group by 1, 2, 3, 4, 5, 6
    )

select
md5(concat(query_id, object_name)) as _unique_id,
*
from access_history_flattened_w_columns
qualify -- added by affinaquest to ensure uniqueness
    row_number() over (
        partition by md5(concat(query_id, object_name)), query_start_time
        order by query_start_time asc
    )
    = 1
order by query_start_time asc
----
-- source: get-select/dbt-snowflake-monitoring models/query_direct_object_access.sql (incremental temp view)
create or replace  temporary view ANALYTICS.DBT_PROD.query_direct_object_access__dbt_tmp
  as (
with
    access_history as (
        select *
        from ANALYTICS.DBT_PROD.stg_access_history



    ),

    access_history_flattened as (
        select
            access_history.query_id,
            access_history.query_start_time,
            access_history.user_name,
            objects_accessed.value:"objectId"::integer as table_id,  -- will be null for secured views or tables from a data share
            objects_accessed.value:"objectName"::text as object_name,
            objects_accessed.value:"objectDomain"::text as object_domain,
            objects_accessed.value:columns as columns_array

        from
            access_history,
            lateral flatten(access_history.direct_objects_accessed) as objects_accessed
    ),

    access_history_flattened_w_columns as (
        select
            access_history_flattened.query_id,
            access_history_flattened.query_start_time,
            access_history_flattened.user_name,
            access_history_flattened.table_id,
            access_history_flattened.object_name,
            access_history_flattened.object_domain,
            array_agg(distinct columns.value:"columnName"::text) as columns_accessed
        from
            access_history_flattened,
            lateral flatten(access_history_flattened.columns_array) as columns
        where access_history_flattened.object_name is not null
        group by 1, 2, 3, 4, 5, 6
    )

select
md5(concat(query_id, object_name)) as _unique_id,
*
from access_history_flattened_w_columns
qualify -- added by affinaquest to ensure uniqueness
    row_number() over (
        partition by md5(concat(query_id, object_name)), query_start_time
        order by query_start_time asc
    )
    = 1
order by query_start_time asc
  )
----
-- source: get-select/dbt-snowflake-monitoring models/query_direct_object_access.sql (incremental merge)
merge into ANALYTICS.DBT_PROD.query_direct_object_access as DBT_INTERNAL_DEST
        using ANALYTICS.DBT_PROD.query_direct_object_access__dbt_tmp as DBT_INTERNAL_SOURCE
        on (
                DBT_INTERNAL_SOURCE.id = DBT_INTERNAL_DEST.id
            )
    when matched then update set
        "ID" = DBT_INTERNAL_SOURCE."ID"
    when not matched then insert
        ("ID")
    values
        ("ID")
----
-- source: get-select/dbt-snowflake-monitoring models/query_direct_table_access.sql (compiled SELECT)
select
    _unique_id,
    query_id,
    query_start_time,
    user_name,
    object_name as full_table_name,
    table_id,
    columns_accessed
from ANALYTICS.DBT_PROD.query_direct_object_access
where
    object_domain = 'Table' -- removes secured views
    and table_id is not null -- removes tables from a data share
----
-- source: get-select/dbt-snowflake-monitoring models/query_direct_table_access.sql (view materialization)
create or replace   view ANALYTICS.DBT_PROD.query_direct_table_access



  as (
    select
    _unique_id,
    query_id,
    query_start_time,
    user_name,
    object_name as full_table_name,
    table_id,
    columns_accessed
from ANALYTICS.DBT_PROD.query_direct_object_access
where
    object_domain = 'Table' -- removes secured views
    and table_id is not null -- removes tables from a data share
  )
----
-- source: get-select/dbt-snowflake-monitoring models/query_history_enriched.sql (compiled SELECT)
with
query_history as (
    select
        *,

        -- this removes comments enclosed by /* <comment text> */ and single line comments starting with -- and either ending with a new line or end of string
        regexp_replace(query_text, $$(\/\*(.|\n|\r)*?\*\/)|(--.*$)|(--.*(\n|\r))|;$$, '') as query_text_no_comments,

        try_parse_json(regexp_substr(query_text, $$\/\*\s*({[^*]*?"app":\s*"dbt"[^*]*})\s*\*\/$$, 1, 1, 'ie')) as _dbt_json_comment_meta,
        case
            when try_parse_json(query_tag)['dbt_snowflake_query_tags_version'] is not null
                or try_parse_json(query_tag)['dbt_query_tags_version'] is not null
            then try_parse_json(query_tag)
        end as _dbt_json_query_tag_meta,
        case
            when _dbt_json_comment_meta is not null or _dbt_json_query_tag_meta is not null then
                map_cat(
                    coalesce(_dbt_json_comment_meta, { })::map(varchar, variant),
                    coalesce(_dbt_json_query_tag_meta, { })::map(varchar, variant)
                )::variant
        end as dbt_metadata

    from ANALYTICS.DBT_PROD.stg_query_history


),

cost_per_query as (
    select *
    from ANALYTICS.DBT_PROD.cost_per_query

)

select
    cost_per_query.query_id,
    cost_per_query.compute_cost,
    cost_per_query.compute_credits,
    cost_per_query.query_acceleration_cost,
    cost_per_query.query_acceleration_credits,
    cost_per_query.cloud_services_cost,
    cost_per_query.cloud_services_credits,
    cost_per_query.query_cost,
    cost_per_query.query_credits,
    cost_per_query.execution_start_time,

    -- Grab all columns from query_history (except the query time columns which we rename below)
    query_history.query_text,
    query_history.database_id,
    query_history.database_name,
    query_history.schema_id,
    query_history.schema_name,
    query_history.query_type,
    query_history.session_id,
    query_history.user_name,
    query_history.role_name,
    query_history.warehouse_id,
    query_history.warehouse_name,
    query_history.warehouse_size,
    query_history.warehouse_type,
    query_history.cluster_number,
    query_history.query_tag,
    query_history.execution_status,
    query_history.error_code,
    query_history.error_message,
    query_history.start_time,
    query_history.end_time,
    query_history.total_elapsed_time,
    query_history.bytes_scanned,
    query_history.percentage_scanned_from_cache,
    query_history.bytes_written,
    query_history.bytes_written_to_result,
    query_history.bytes_read_from_result,
    query_history.rows_produced,
    query_history.rows_inserted,
    query_history.rows_updated,
    query_history.rows_deleted,
    query_history.rows_unloaded,
    query_history.bytes_deleted,
    query_history.partitions_scanned,
    query_history.partitions_total,
    query_history.bytes_spilled_to_local_storage,
    query_history.bytes_spilled_to_remote_storage,
    query_history.bytes_sent_over_the_network,
    query_history.outbound_data_transfer_cloud,
    query_history.outbound_data_transfer_region,
    query_history.outbound_data_transfer_bytes,
    query_history.inbound_data_transfer_cloud,
    query_history.inbound_data_transfer_region,
    query_history.inbound_data_transfer_bytes,
    query_history.credits_used_cloud_services,
    query_history.release_version,
    query_history.external_function_total_invocations,
    query_history.external_function_total_sent_rows,
    query_history.external_function_total_received_rows,
    query_history.external_function_total_sent_bytes,
    query_history.external_function_total_received_bytes,
    query_history.query_load_percent,
    query_history.is_client_generated_statement,
    query_history.query_acceleration_bytes_scanned,
    query_history.query_acceleration_partitions_scanned,
    query_history.query_acceleration_upper_limit_scale_factor,
    query_history.query_hash,
    query_history.query_hash_version,
    query_history.query_parameterized_hash,
    query_history.query_parameterized_hash_version,

    -- Rename some existing columns for clarity
    query_history.total_elapsed_time as total_elapsed_time_ms,
    query_history.compilation_time as compilation_time_ms,
    query_history.queued_provisioning_time as queued_provisioning_time_ms,
    query_history.queued_repair_time as queued_repair_time_ms,
    query_history.queued_overload_time as queued_overload_time_ms,
    query_history.transaction_blocked_time as transaction_blocked_time_ms,
    query_history.list_external_files_time as list_external_files_time_ms,
    query_history.execution_time as execution_time_ms,

    -- New columns
    query_history.warehouse_size is not null as ran_on_warehouse,
    query_history.bytes_scanned / power(1024, 3) as data_scanned_gb,
    data_scanned_gb * query_history.percentage_scanned_from_cache as data_scanned_from_cache_gb,
    query_history.bytes_spilled_to_local_storage / power(1024, 3) as data_spilled_to_local_storage_gb,
    query_history.bytes_spilled_to_remote_storage / power(1024, 3) as data_spilled_to_remote_storage_gb,
    query_history.bytes_sent_over_the_network / power(1024, 3) as data_sent_over_the_network_gb,
    query_history.query_text_no_comments,
    query_history.dbt_metadata,

    query_history.total_elapsed_time / 1000 as total_elapsed_time_s,
    query_history.compilation_time / 1000 as compilation_time_s,
    query_history.queued_provisioning_time / 1000 as queued_provisioning_time_s,
    query_history.queued_repair_time / 1000 as queued_repair_time_s,
    query_history.queued_overload_time / 1000 as queued_overload_time_s,
    query_history.transaction_blocked_time / 1000 as transaction_blocked_time_s,
    query_history.list_external_files_time / 1000 as list_external_files_time_s,
    query_history.execution_time / 1000 as execution_time_s,
    cost_per_query.currency,
    query_history.query_retry_time as query_retry_time_ms,
    query_history.query_retry_time / 1000 as query_retry_time_s,
    query_history.query_retry_cause,
    query_history.fault_handling_time as fault_handling_time_ms,
    query_history.fault_handling_time / 1000 as fault_handling_time_s

from query_history
inner join cost_per_query
    on query_history.query_id = cost_per_query.query_id
order by query_history.start_time
----
-- source: get-select/dbt-snowflake-monitoring models/query_history_enriched.sql (incremental temp view)
create or replace  temporary view ANALYTICS.DBT_PROD.query_history_enriched__dbt_tmp
  as (
with
query_history as (
    select
        *,

        -- this removes comments enclosed by /* <comment text> */ and single line comments starting with -- and either ending with a new line or end of string
        regexp_replace(query_text, $$(\/\*(.|\n|\r)*?\*\/)|(--.*$)|(--.*(\n|\r))|;$$, '') as query_text_no_comments,

        try_parse_json(regexp_substr(query_text, $$\/\*\s*({[^*]*?"app":\s*"dbt"[^*]*})\s*\*\/$$, 1, 1, 'ie')) as _dbt_json_comment_meta,
        case
            when try_parse_json(query_tag)['dbt_snowflake_query_tags_version'] is not null
                or try_parse_json(query_tag)['dbt_query_tags_version'] is not null
            then try_parse_json(query_tag)
        end as _dbt_json_query_tag_meta,
        case
            when _dbt_json_comment_meta is not null or _dbt_json_query_tag_meta is not null then
                map_cat(
                    coalesce(_dbt_json_comment_meta, { })::map(varchar, variant),
                    coalesce(_dbt_json_query_tag_meta, { })::map(varchar, variant)
                )::variant
        end as dbt_metadata

    from ANALYTICS.DBT_PROD.stg_query_history


),

cost_per_query as (
    select *
    from ANALYTICS.DBT_PROD.cost_per_query

)

select
    cost_per_query.query_id,
    cost_per_query.compute_cost,
    cost_per_query.compute_credits,
    cost_per_query.query_acceleration_cost,
    cost_per_query.query_acceleration_credits,
    cost_per_query.cloud_services_cost,
    cost_per_query.cloud_services_credits,
    cost_per_query.query_cost,
    cost_per_query.query_credits,
    cost_per_query.execution_start_time,

    -- Grab all columns from query_history (except the query time columns which we rename below)
    query_history.query_text,
    query_history.database_id,
    query_history.database_name,
    query_history.schema_id,
    query_history.schema_name,
    query_history.query_type,
    query_history.session_id,
    query_history.user_name,
    query_history.role_name,
    query_history.warehouse_id,
    query_history.warehouse_name,
    query_history.warehouse_size,
    query_history.warehouse_type,
    query_history.cluster_number,
    query_history.query_tag,
    query_history.execution_status,
    query_history.error_code,
    query_history.error_message,
    query_history.start_time,
    query_history.end_time,
    query_history.total_elapsed_time,
    query_history.bytes_scanned,
    query_history.percentage_scanned_from_cache,
    query_history.bytes_written,
    query_history.bytes_written_to_result,
    query_history.bytes_read_from_result,
    query_history.rows_produced,
    query_history.rows_inserted,
    query_history.rows_updated,
    query_history.rows_deleted,
    query_history.rows_unloaded,
    query_history.bytes_deleted,
    query_history.partitions_scanned,
    query_history.partitions_total,
    query_history.bytes_spilled_to_local_storage,
    query_history.bytes_spilled_to_remote_storage,
    query_history.bytes_sent_over_the_network,
    query_history.outbound_data_transfer_cloud,
    query_history.outbound_data_transfer_region,
    query_history.outbound_data_transfer_bytes,
    query_history.inbound_data_transfer_cloud,
    query_history.inbound_data_transfer_region,
    query_history.inbound_data_transfer_bytes,
    query_history.credits_used_cloud_services,
    query_history.release_version,
    query_history.external_function_total_invocations,
    query_history.external_function_total_sent_rows,
    query_history.external_function_total_received_rows,
    query_history.external_function_total_sent_bytes,
    query_history.external_function_total_received_bytes,
    query_history.query_load_percent,
    query_history.is_client_generated_statement,
    query_history.query_acceleration_bytes_scanned,
    query_history.query_acceleration_partitions_scanned,
    query_history.query_acceleration_upper_limit_scale_factor,
    query_history.query_hash,
    query_history.query_hash_version,
    query_history.query_parameterized_hash,
    query_history.query_parameterized_hash_version,

    -- Rename some existing columns for clarity
    query_history.total_elapsed_time as total_elapsed_time_ms,
    query_history.compilation_time as compilation_time_ms,
    query_history.queued_provisioning_time as queued_provisioning_time_ms,
    query_history.queued_repair_time as queued_repair_time_ms,
    query_history.queued_overload_time as queued_overload_time_ms,
    query_history.transaction_blocked_time as transaction_blocked_time_ms,
    query_history.list_external_files_time as list_external_files_time_ms,
    query_history.execution_time as execution_time_ms,

    -- New columns
    query_history.warehouse_size is not null as ran_on_warehouse,
    query_history.bytes_scanned / power(1024, 3) as data_scanned_gb,
    data_scanned_gb * query_history.percentage_scanned_from_cache as data_scanned_from_cache_gb,
    query_history.bytes_spilled_to_local_storage / power(1024, 3) as data_spilled_to_local_storage_gb,
    query_history.bytes_spilled_to_remote_storage / power(1024, 3) as data_spilled_to_remote_storage_gb,
    query_history.bytes_sent_over_the_network / power(1024, 3) as data_sent_over_the_network_gb,
    query_history.query_text_no_comments,
    query_history.dbt_metadata,

    query_history.total_elapsed_time / 1000 as total_elapsed_time_s,
    query_history.compilation_time / 1000 as compilation_time_s,
    query_history.queued_provisioning_time / 1000 as queued_provisioning_time_s,
    query_history.queued_repair_time / 1000 as queued_repair_time_s,
    query_history.queued_overload_time / 1000 as queued_overload_time_s,
    query_history.transaction_blocked_time / 1000 as transaction_blocked_time_s,
    query_history.list_external_files_time / 1000 as list_external_files_time_s,
    query_history.execution_time / 1000 as execution_time_s,
    cost_per_query.currency,
    query_history.query_retry_time as query_retry_time_ms,
    query_history.query_retry_time / 1000 as query_retry_time_s,
    query_history.query_retry_cause,
    query_history.fault_handling_time as fault_handling_time_ms,
    query_history.fault_handling_time / 1000 as fault_handling_time_s

from query_history
inner join cost_per_query
    on query_history.query_id = cost_per_query.query_id
order by query_history.start_time
  )
----
-- source: get-select/dbt-snowflake-monitoring models/query_history_enriched.sql (incremental merge)
merge into ANALYTICS.DBT_PROD.query_history_enriched as DBT_INTERNAL_DEST
        using ANALYTICS.DBT_PROD.query_history_enriched__dbt_tmp as DBT_INTERNAL_SOURCE
        on (
                DBT_INTERNAL_SOURCE.id = DBT_INTERNAL_DEST.id
            )
    when matched then update set
        "ID" = DBT_INTERNAL_SOURCE."ID"
    when not matched then insert
        ("ID")
    values
        ("ID")
----
-- source: get-select/dbt-snowflake-monitoring models/remaining_balance_daily_without_contract_view.sql (compiled SELECT)
select
    date,
    organization_name,
    currency,
    free_usage_balance,
    capacity_balance,
    on_demand_consumption_balance,
    rollover_balance
from ANALYTICS.DBT_PROD.stg_remaining_balance_daily

qualify row_number() over (partition by date
order by contract_number desc nulls last) = 1
----
-- source: get-select/dbt-snowflake-monitoring models/remaining_balance_daily_without_contract_view.sql (view materialization)
create or replace   view ANALYTICS.DBT_PROD.remaining_balance_daily_without_contract_view



  as (
    select
    date,
    organization_name,
    currency,
    free_usage_balance,
    capacity_balance,
    on_demand_consumption_balance,
    rollover_balance
from ANALYTICS.DBT_PROD.stg_remaining_balance_daily

qualify row_number() over (partition by date
order by contract_number desc nulls last) = 1
  )
----
-- source: get-select/dbt-snowflake-monitoring models/warehouse_credits_map.sql (compiled SELECT)
with
warehouse_credits_map as (
    select * from (
        values
        ('X-Small', 'STANDARD', 1),
        ('Small', 'STANDARD', 2),
        ('Medium', 'STANDARD', 4),
        ('Large', 'STANDARD', 8),
        ('X-Large', 'STANDARD', 16),
        ('2X-Large', 'STANDARD', 32),
        ('3X-Large', 'STANDARD', 64),
        ('4X-Large', 'STANDARD', 128),
        ('5X-Large', 'STANDARD', 256),
        ('6X-Large', 'STANDARD', 512),
        ('Medium', 'SNOWPARK-OPTIMIZED', 6),
        ('Large', 'SNOWPARK-OPTIMIZED', 12),
        ('X-Large', 'SNOWPARK-OPTIMIZED', 24),
        ('2X-Large', 'SNOWPARK-OPTIMIZED', 48),
        ('3X-Large', 'SNOWPARK-OPTIMIZED', 96),
        ('4X-Large', 'SNOWPARK-OPTIMIZED', 192),
        ('5X-Large', 'SNOWPARK-OPTIMIZED', 384),
        ('6X-Large', 'SNOWPARK-OPTIMIZED', 768)
    ) as t (warehouse_size, warehouse_type, credits_per_hour)
)

select
    warehouse_size,
    warehouse_type,
    credits_per_hour,
    credits_per_hour / 60 as credits_per_minute,
    credits_per_hour / 3600 as credits_per_second
from warehouse_credits_map
----
-- source: get-select/dbt-snowflake-monitoring models/warehouse_credits_map.sql (view materialization)
create or replace   view ANALYTICS.DBT_PROD.warehouse_credits_map



  as (
    with
warehouse_credits_map as (
    select * from (
        values
        ('X-Small', 'STANDARD', 1),
        ('Small', 'STANDARD', 2),
        ('Medium', 'STANDARD', 4),
        ('Large', 'STANDARD', 8),
        ('X-Large', 'STANDARD', 16),
        ('2X-Large', 'STANDARD', 32),
        ('3X-Large', 'STANDARD', 64),
        ('4X-Large', 'STANDARD', 128),
        ('5X-Large', 'STANDARD', 256),
        ('6X-Large', 'STANDARD', 512),
        ('Medium', 'SNOWPARK-OPTIMIZED', 6),
        ('Large', 'SNOWPARK-OPTIMIZED', 12),
        ('X-Large', 'SNOWPARK-OPTIMIZED', 24),
        ('2X-Large', 'SNOWPARK-OPTIMIZED', 48),
        ('3X-Large', 'SNOWPARK-OPTIMIZED', 96),
        ('4X-Large', 'SNOWPARK-OPTIMIZED', 192),
        ('5X-Large', 'SNOWPARK-OPTIMIZED', 384),
        ('6X-Large', 'SNOWPARK-OPTIMIZED', 768)
    ) as t (warehouse_size, warehouse_type, credits_per_hour)
)

select
    warehouse_size,
    warehouse_type,
    credits_per_hour,
    credits_per_hour / 60 as credits_per_minute,
    credits_per_hour / 3600 as credits_per_second
from warehouse_credits_map
  )
----
-- source: get-select/dbt-snowflake-monitoring models/warehouses_type2_dimension.sql (compiled SELECT)
with
stop_threshold as (
    select max(start_time) as timestamp
    from ANALYTICS.DBT_PROD.stg_query_history
),

warehouse_snapshots_base as (
    select
        warehouse_id,
        warehouse_size,
        warehouse_name,
        start_time as timestamp,
        lag(warehouse_size) over (partition by warehouse_id
order by start_time) as prev_warehouse_size,
        lag(warehouse_name) over (partition by warehouse_id
order by start_time) as prev_warehouse_name
    from ANALYTICS.DBT_PROD.stg_query_history
    where
        warehouse_size is not null
),

warehouse_snapshots as (
    select
        warehouse_id,
        warehouse_name,
        warehouse_size,
        timestamp as valid_from,
        lead(timestamp) over (partition by warehouse_id
order by timestamp) as _valid_to
    from warehouse_snapshots_base
    where
        warehouse_size != coalesce(prev_warehouse_size, '')
        or warehouse_name != coalesce(prev_warehouse_name, '')
)

select
    warehouse_snapshots.warehouse_id,
    warehouse_snapshots.warehouse_name,
    warehouse_snapshots.warehouse_size,
    warehouse_snapshots.valid_from,
    coalesce(warehouse_snapshots._valid_to, stop_threshold.timestamp) as valid_to,
    warehouse_snapshots._valid_to is null as is_current
from warehouse_snapshots
cross join stop_threshold
----
-- source: get-select/dbt-snowflake-monitoring models/warehouses_type2_dimension.sql (table materialization)
create or replace transient table ANALYTICS.DBT_PROD.warehouses_type2_dimension
    as
    (
with
stop_threshold as (
    select max(start_time) as timestamp
    from ANALYTICS.DBT_PROD.stg_query_history
),

warehouse_snapshots_base as (
    select
        warehouse_id,
        warehouse_size,
        warehouse_name,
        start_time as timestamp,
        lag(warehouse_size) over (partition by warehouse_id
order by start_time) as prev_warehouse_size,
        lag(warehouse_name) over (partition by warehouse_id
order by start_time) as prev_warehouse_name
    from ANALYTICS.DBT_PROD.stg_query_history
    where
        warehouse_size is not null
),

warehouse_snapshots as (
    select
        warehouse_id,
        warehouse_name,
        warehouse_size,
        timestamp as valid_from,
        lead(timestamp) over (partition by warehouse_id
order by timestamp) as _valid_to
    from warehouse_snapshots_base
    where
        warehouse_size != coalesce(prev_warehouse_size, '')
        or warehouse_name != coalesce(prev_warehouse_name, '')
)

select
    warehouse_snapshots.warehouse_id,
    warehouse_snapshots.warehouse_name,
    warehouse_snapshots.warehouse_size,
    warehouse_snapshots.valid_from,
    coalesce(warehouse_snapshots._valid_to, stop_threshold.timestamp) as valid_to,
    warehouse_snapshots._valid_to is null as is_current
from warehouse_snapshots
cross join stop_threshold
    )
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_access_history.sql (compiled SELECT)
select
    query_id,
    parent_query_id,
    root_query_id,
    query_start_time,
    user_name,
    direct_objects_accessed,
    base_objects_accessed,
    objects_modified
from RAW.snowflake_account_usage.access_history



order by query_start_time asc
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_access_history.sql (incremental temp view)
create or replace  temporary view ANALYTICS.DBT_PROD.stg_access_history__dbt_tmp
  as (
select
    query_id,
    parent_query_id,
    root_query_id,
    query_start_time,
    user_name,
    direct_objects_accessed,
    base_objects_accessed,
    objects_modified
from RAW.snowflake_account_usage.access_history



order by query_start_time asc
  )
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_access_history.sql (incremental merge)
merge into ANALYTICS.DBT_PROD.stg_access_history as DBT_INTERNAL_DEST
        using ANALYTICS.DBT_PROD.stg_access_history__dbt_tmp as DBT_INTERNAL_SOURCE
        on (
                DBT_INTERNAL_SOURCE.id = DBT_INTERNAL_DEST.id
            )
    when matched then update set
        "ID" = DBT_INTERNAL_SOURCE."ID"
    when not matched then insert
        ("ID")
    values
        ("ID")
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_database_storage_usage_history.sql (compiled SELECT)
select
    usage_date as date,
    database_name,
    average_database_bytes,
    average_failsafe_bytes,
    average_hybrid_table_storage_bytes
from RAW.snowflake_account_usage.database_storage_usage_history
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_database_storage_usage_history.sql (view materialization)
create or replace   view ANALYTICS.DBT_PROD.stg_database_storage_usage_history



  as (
    select
    usage_date as date,
    database_name,
    average_database_bytes,
    average_failsafe_bytes,
    average_hybrid_table_storage_bytes
from RAW.snowflake_account_usage.database_storage_usage_history
  )
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_metering_daily_history.sql (compiled SELECT)
select
    usage_date as date,
    service_type,
    credits_used_cloud_services,
    credits_adjustment_cloud_services
from RAW.snowflake_account_usage.metering_daily_history
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_metering_daily_history.sql (view materialization)
create or replace   view ANALYTICS.DBT_PROD.stg_metering_daily_history



  as (
    select
    usage_date as date,
    service_type,
    credits_used_cloud_services,
    credits_adjustment_cloud_services
from RAW.snowflake_account_usage.metering_daily_history
  )
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_metering_history.sql (compiled SELECT)
select
    service_type,
    start_time,
    end_time,
    entity_id,
    name,
    credits_used_compute,
    credits_used_cloud_services,
    credits_used
from RAW.snowflake_account_usage.metering_history
order by start_time asc
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_metering_history.sql (table materialization)
create or replace transient table ANALYTICS.DBT_PROD.stg_metering_history
    as
    (
select
    service_type,
    start_time,
    end_time,
    entity_id,
    name,
    credits_used_compute,
    credits_used_cloud_services,
    credits_used
from RAW.snowflake_account_usage.metering_history
order by start_time asc
    )
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_query_history.sql (compiled SELECT)
select
    query_id,
    query_text,
    database_id,
    database_name,
    schema_id,
    schema_name,
    query_type,
    session_id,
    user_name,
    role_name,
    warehouse_id,
    warehouse_name,
    warehouse_size,
    warehouse_type,
    cluster_number,
    query_tag,
    execution_status,
    error_code,
    error_message,
    start_time,
    end_time,
    total_elapsed_time,
    bytes_scanned,
    percentage_scanned_from_cache,
    bytes_written,
    bytes_written_to_result,
    bytes_read_from_result,
    rows_produced,
    rows_inserted,
    rows_updated,
    rows_deleted,
    rows_unloaded,
    bytes_deleted,
    partitions_scanned,
    partitions_total,
    bytes_spilled_to_local_storage,
    bytes_spilled_to_remote_storage,
    bytes_sent_over_the_network,
    compilation_time,
    execution_time,
    queued_provisioning_time,
    queued_repair_time,
    queued_overload_time,
    transaction_blocked_time,
    outbound_data_transfer_cloud,
    outbound_data_transfer_region,
    outbound_data_transfer_bytes,
    inbound_data_transfer_cloud,
    inbound_data_transfer_region,
    inbound_data_transfer_bytes,
    list_external_files_time,
    credits_used_cloud_services,
    release_version,
    external_function_total_invocations,
    external_function_total_sent_rows,
    external_function_total_received_rows,
    external_function_total_sent_bytes,
    external_function_total_received_bytes,
    query_load_percent,
    is_client_generated_statement,
    query_acceleration_bytes_scanned,
    query_acceleration_partitions_scanned,
    query_acceleration_upper_limit_scale_factor,
    query_hash,
    query_hash_version,
    query_parameterized_hash,
    query_parameterized_hash_version,
    query_retry_time,
    query_retry_cause,
    fault_handling_time
from RAW.snowflake_account_usage.query_history



qualify row_number() over (partition by query_id order by start_time ) = 1

order by start_time
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_query_history.sql (incremental temp view)
create or replace  temporary view ANALYTICS.DBT_PROD.stg_query_history__dbt_tmp
  as (
select
    query_id,
    query_text,
    database_id,
    database_name,
    schema_id,
    schema_name,
    query_type,
    session_id,
    user_name,
    role_name,
    warehouse_id,
    warehouse_name,
    warehouse_size,
    warehouse_type,
    cluster_number,
    query_tag,
    execution_status,
    error_code,
    error_message,
    start_time,
    end_time,
    total_elapsed_time,
    bytes_scanned,
    percentage_scanned_from_cache,
    bytes_written,
    bytes_written_to_result,
    bytes_read_from_result,
    rows_produced,
    rows_inserted,
    rows_updated,
    rows_deleted,
    rows_unloaded,
    bytes_deleted,
    partitions_scanned,
    partitions_total,
    bytes_spilled_to_local_storage,
    bytes_spilled_to_remote_storage,
    bytes_sent_over_the_network,
    compilation_time,
    execution_time,
    queued_provisioning_time,
    queued_repair_time,
    queued_overload_time,
    transaction_blocked_time,
    outbound_data_transfer_cloud,
    outbound_data_transfer_region,
    outbound_data_transfer_bytes,
    inbound_data_transfer_cloud,
    inbound_data_transfer_region,
    inbound_data_transfer_bytes,
    list_external_files_time,
    credits_used_cloud_services,
    release_version,
    external_function_total_invocations,
    external_function_total_sent_rows,
    external_function_total_received_rows,
    external_function_total_sent_bytes,
    external_function_total_received_bytes,
    query_load_percent,
    is_client_generated_statement,
    query_acceleration_bytes_scanned,
    query_acceleration_partitions_scanned,
    query_acceleration_upper_limit_scale_factor,
    query_hash,
    query_hash_version,
    query_parameterized_hash,
    query_parameterized_hash_version,
    query_retry_time,
    query_retry_cause,
    fault_handling_time
from RAW.snowflake_account_usage.query_history



qualify row_number() over (partition by query_id order by start_time ) = 1

order by start_time
  )
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_query_history.sql (incremental merge)
merge into ANALYTICS.DBT_PROD.stg_query_history as DBT_INTERNAL_DEST
        using ANALYTICS.DBT_PROD.stg_query_history__dbt_tmp as DBT_INTERNAL_SOURCE
        on (
                DBT_INTERNAL_SOURCE.id = DBT_INTERNAL_DEST.id
            )
    when matched then update set
        "ID" = DBT_INTERNAL_SOURCE."ID"
    when not matched then insert
        ("ID")
    values
        ("ID")
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_rate_sheet_daily.sql (compiled SELECT)
-- <1000 rows, will be more expensive to materialize incrementally with multiple SQL statements


select
    date,
    organization_name,
    contract_number,
    account_name,
    account_locator,
    region,
    service_level,
    usage_type,
    currency,
    effective_rate,
    service_type
from RAW.snowflake_organization_usage.rate_sheet_daily
order by date
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_rate_sheet_daily.sql (table materialization)
create or replace transient table ANALYTICS.DBT_PROD.stg_rate_sheet_daily
    as
    (
-- <1000 rows, will be more expensive to materialize incrementally with multiple SQL statements


select
    date,
    organization_name,
    contract_number,
    account_name,
    account_locator,
    region,
    service_level,
    usage_type,
    currency,
    effective_rate,
    service_type
from RAW.snowflake_organization_usage.rate_sheet_daily
order by date
    )
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_remaining_balance_daily.sql (compiled SELECT)
-- <1000 rows, will be more expensive to materialize incrementally with multiple SQL statements


select
    date,
    organization_name,
    contract_number,
    currency,
    free_usage_balance,
    capacity_balance,
    on_demand_consumption_balance,
    rollover_balance
from RAW.snowflake_organization_usage.remaining_balance_daily
order by date
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_remaining_balance_daily.sql (table materialization)
create or replace transient table ANALYTICS.DBT_PROD.stg_remaining_balance_daily
    as
    (
-- <1000 rows, will be more expensive to materialize incrementally with multiple SQL statements


select
    date,
    organization_name,
    contract_number,
    currency,
    free_usage_balance,
    capacity_balance,
    on_demand_consumption_balance,
    rollover_balance
from RAW.snowflake_organization_usage.remaining_balance_daily
order by date
    )
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_serverless_task_history.sql (compiled SELECT)
select
    start_time,
    end_time,
    task_id,
    task_name,
    schema_id,
    schema_name,
    database_id,
    database_name,
    credits_used
from RAW.snowflake_account_usage.serverless_task_history



order by start_time
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_serverless_task_history.sql (incremental temp view)
create or replace  temporary view ANALYTICS.DBT_PROD.stg_serverless_task_history__dbt_tmp
  as (
select
    start_time,
    end_time,
    task_id,
    task_name,
    schema_id,
    schema_name,
    database_id,
    database_name,
    credits_used
from RAW.snowflake_account_usage.serverless_task_history



order by start_time
  )
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_serverless_task_history.sql (incremental merge)
merge into ANALYTICS.DBT_PROD.stg_serverless_task_history as DBT_INTERNAL_DEST
        using ANALYTICS.DBT_PROD.stg_serverless_task_history__dbt_tmp as DBT_INTERNAL_SOURCE
        on (
                DBT_INTERNAL_SOURCE.id = DBT_INTERNAL_DEST.id
            )
    when matched then update set
        "ID" = DBT_INTERNAL_SOURCE."ID"
    when not matched then insert
        ("ID")
    values
        ("ID")
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_stage_storage_usage_history.sql (compiled SELECT)
select
    usage_date as date,
    average_stage_bytes
from RAW.snowflake_account_usage.stage_storage_usage_history
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_stage_storage_usage_history.sql (view materialization)
create or replace   view ANALYTICS.DBT_PROD.stg_stage_storage_usage_history



  as (
    select
    usage_date as date,
    average_stage_bytes
from RAW.snowflake_account_usage.stage_storage_usage_history
  )
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_storage_usage.sql (compiled SELECT)
select
    usage_date as date,
    storage_bytes,
    stage_bytes,
    failsafe_bytes,
    hybrid_table_storage_bytes,
    archive_storage_cool_bytes,
    archive_storage_cold_bytes,
    archive_storage_retrieval_temp_bytes
from RAW.snowflake_account_usage.storage_usage
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_storage_usage.sql (view materialization)
create or replace   view ANALYTICS.DBT_PROD.stg_storage_usage



  as (
    select
    usage_date as date,
    storage_bytes,
    stage_bytes,
    failsafe_bytes,
    hybrid_table_storage_bytes,
    archive_storage_cool_bytes,
    archive_storage_cold_bytes,
    archive_storage_retrieval_temp_bytes
from RAW.snowflake_account_usage.storage_usage
  )
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_usage_in_currency_daily.sql (compiled SELECT)
select
    organization_name,
    contract_number,
    account_name,
    account_locator,
    region,
    service_level,
    usage_date,
    usage_type,
    currency,
    usage,
    usage_in_currency,
    balance_source,
    billing_type,
    rating_type,
    service_type,
    is_adjustment
from RAW.snowflake_organization_usage.usage_in_currency_daily
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_usage_in_currency_daily.sql (view materialization)
create or replace   view ANALYTICS.DBT_PROD.stg_usage_in_currency_daily



  as (
    select
    organization_name,
    contract_number,
    account_name,
    account_locator,
    region,
    service_level,
    usage_date,
    usage_type,
    currency,
    usage,
    usage_in_currency,
    balance_source,
    billing_type,
    rating_type,
    service_type,
    is_adjustment
from RAW.snowflake_organization_usage.usage_in_currency_daily
  )
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_warehouse_metering_history.sql (compiled SELECT)
select
    start_time,
    end_time,
    warehouse_id,
    warehouse_name,
    credits_used,
    credits_used_compute,
    credits_used_cloud_services
from RAW.snowflake_account_usage.warehouse_metering_history



order by start_time
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_warehouse_metering_history.sql (incremental temp view)
create or replace  temporary view ANALYTICS.DBT_PROD.stg_warehouse_metering_history__dbt_tmp
  as (
select
    start_time,
    end_time,
    warehouse_id,
    warehouse_name,
    credits_used,
    credits_used_compute,
    credits_used_cloud_services
from RAW.snowflake_account_usage.warehouse_metering_history



order by start_time
  )
----
-- source: get-select/dbt-snowflake-monitoring models/staging/stg_warehouse_metering_history.sql (incremental merge)
merge into ANALYTICS.DBT_PROD.stg_warehouse_metering_history as DBT_INTERNAL_DEST
        using ANALYTICS.DBT_PROD.stg_warehouse_metering_history__dbt_tmp as DBT_INTERNAL_SOURCE
        on (
                DBT_INTERNAL_SOURCE.id = DBT_INTERNAL_DEST.id
            )
    when matched then update set
        "ID" = DBT_INTERNAL_SOURCE."ID"
    when not matched then insert
        ("ID")
    values
        ("ID")
----
-- source: dbt-snowflake adapter statement shapes
alter session set query_tag = '{"app": "dbt", "dbt_version": "1.9.0", "node_id": "model.jaffle_shop.orders"}'
----
-- source: dbt-snowflake adapter statement shapes
alter session unset query_tag
----
-- source: dbt-snowflake adapter statement shapes
show terse schemas in database ANALYTICS limit 10000
----
-- source: dbt-snowflake adapter statement shapes
show objects in ANALYTICS.DBT_PROD limit 10000
----
-- source: dbt-snowflake adapter statement shapes
show terse objects in schema ANALYTICS.DBT_PROD
----
-- source: dbt-snowflake adapter statement shapes
describe table ANALYTICS.DBT_PROD.orders
----
-- source: dbt-snowflake adapter statement shapes
select current_warehouse() as warehouse
----
-- source: dbt-snowflake adapter statement shapes
use warehouse TRANSFORMING_XS
----
-- source: dbt-snowflake adapter statement shapes
create or replace transient table ANALYTICS.DBT_PROD.orders
    copy grants
    as
    (
select order_id, customer_id, order_date, status, amount from ANALYTICS.DBT_PROD.stg_orders
    )
----
-- source: dbt-snowflake adapter statement shapes
create or replace temporary table ANALYTICS.DBT_PROD.orders__dbt_tmp
    as
    (
select order_id, customer_id, order_date, status, amount from ANALYTICS.DBT_PROD.stg_orders where order_date > dateadd(day, -3, current_date)
    )
----
-- source: dbt-snowflake adapter statement shapes
create or replace   view ANALYTICS.DBT_PROD.stg_orders
  copy grants
  as (
    select id as order_id, user_id as customer_id, order_date, status from RAW.jaffle_shop.orders
  )
----
-- source: dbt-snowflake adapter statement shapes
merge into ANALYTICS.DBT_PROD.orders as DBT_INTERNAL_DEST
        using ANALYTICS.DBT_PROD.orders__dbt_tmp as DBT_INTERNAL_SOURCE
        on (
                DBT_INTERNAL_SOURCE.order_id = DBT_INTERNAL_DEST.order_id
            )
    when matched then update set
        "ORDER_ID" = DBT_INTERNAL_SOURCE."ORDER_ID","STATUS" = DBT_INTERNAL_SOURCE."STATUS"
    when not matched then insert
        ("ORDER_ID", "STATUS")
    values
        ("ORDER_ID", "STATUS")
----
-- source: dbt-snowflake adapter statement shapes
delete from ANALYTICS.DBT_PROD.orders
            where (
                order_id) in (
                select (order_id)
                from ANALYTICS.DBT_PROD.orders__dbt_tmp
            )
----
-- source: dbt-snowflake adapter statement shapes
insert into ANALYTICS.DBT_PROD.orders ("ORDER_ID", "STATUS")
    (
        select "ORDER_ID", "STATUS"
        from ANALYTICS.DBT_PROD.orders__dbt_tmp
    )
----
-- source: dbt-snowflake adapter statement shapes
insert overwrite into ANALYTICS.DBT_PROD.orders ("ORDER_ID", "STATUS")
    (
        select "ORDER_ID", "STATUS"
        from ANALYTICS.DBT_PROD.orders__dbt_tmp
    )
----
-- source: dbt-snowflake adapter statement shapes
alter table ANALYTICS.DBT_PROD.orders__dbt_tmp rename to ANALYTICS.DBT_PROD.orders
----
-- source: dbt-snowflake adapter statement shapes
alter table ANALYTICS.DBT_PROD.orders swap with ANALYTICS.DBT_PROD.orders__dbt_backup
----
-- source: dbt-snowflake adapter statement shapes
drop table if exists ANALYTICS.DBT_PROD.orders__dbt_backup cascade
----
-- source: dbt-snowflake adapter statement shapes
drop view if exists ANALYTICS.DBT_PROD.stg_orders cascade
----
-- source: dbt-snowflake adapter statement shapes
drop dynamic table if exists ANALYTICS.DBT_PROD.orders_dt
----
-- source: dbt-snowflake adapter statement shapes
create or replace transient table ANALYTICS.DBT_PROD.orders_clone clone ANALYTICS.DBT_PROD.orders
----
-- source: dbt-snowflake adapter statement shapes
comment on table ANALYTICS.DBT_PROD.orders IS $$One row per order$$
----
-- source: dbt-snowflake adapter statement shapes
comment on column ANALYTICS.DBT_PROD.orders.status IS $$Order status$$
----
-- source: dbt-snowflake adapter statement shapes
alter table ANALYTICS.DBT_PROD.orders alter "STATUS" comment $$Order status$$
----
-- source: dbt-snowflake adapter statement shapes
alter table ANALYTICS.DBT_PROD.orders add column "DISCOUNT" number(38,2)
----
-- source: dbt-snowflake adapter statement shapes
alter table ANALYTICS.DBT_PROD.orders drop column "LEGACY_FLAG"
----
-- source: dbt-snowflake adapter statement shapes
alter table ANALYTICS.DBT_PROD.orders alter "AMOUNT" set data type number(38,4)
----
-- source: dbt-snowflake adapter statement shapes
alter table ANALYTICS.DBT_PROD.orders cluster by (order_date)
----
-- source: dbt-snowflake adapter statement shapes
grant select on ANALYTICS.DBT_PROD.orders to role REPORTER
----
-- source: dbt-snowflake adapter statement shapes
revoke select on ANALYTICS.DBT_PROD.orders from role REPORTER
----
-- source: dbt-snowflake adapter statement shapes
show grants on ANALYTICS.DBT_PROD.orders
----
-- source: dbt-snowflake adapter statement shapes
truncate table ANALYTICS.DBT_PROD.orders
----
-- source: dbt-snowflake adapter statement shapes
create or replace dynamic table ANALYTICS.DBT_PROD.orders_dt
        target_lag = '1 hour'
        warehouse = TRANSFORMING_XS
        refresh_mode = AUTO
        initialize = ON_CREATE
        as (
            select order_id, status from ANALYTICS.DBT_PROD.stg_orders
        )
----
-- source: dbt-snowflake adapter statement shapes
alter dynamic table ANALYTICS.DBT_PROD.orders_dt refresh
----
-- source: dbt-snowflake adapter statement shapes
alter dynamic table ANALYTICS.DBT_PROD.orders_dt set target_lag = '2 hours' warehouse = TRANSFORMING_S
----
-- source: dbt-snowflake adapter statement shapes
create table ANALYTICS.DBT_PROD.raw_customers ("ID" integer, "FIRST_NAME" varchar, "LAST_NAME" varchar)
----
-- source: dbt-snowflake adapter statement shapes
insert into ANALYTICS.DBT_PROD.raw_customers ("ID", "FIRST_NAME", "LAST_NAME") values (1, 'Michael', 'P.'), (2, 'Shawn', 'M.')
----
-- source: dbt-snowflake adapter statement shapes
select table_catalog as "table_database", table_schema as "table_schema", table_name as "table_name", coalesce(table_type, 'DYNAMIC TABLE') as "table_type", comment as "table_comment", table_owner as "table_owner", 'Clustering Key' as "stats:clustering_key:label", clustering_key as "stats:clustering_key:value" from ANALYTICS.INFORMATION_SCHEMA.tables where (upper("table_schema") ilike 'DBT_PROD')
----
-- source: dbt-snowflake adapter statement shapes
select count(*) as failures, count(*) != 0 as should_warn, count(*) != 0 as should_error from ( select order_id from ANALYTICS.DBT_PROD.orders where order_id is null ) dbt_internal_test
----
-- source: dbt-snowflake adapter statement shapes
begin
----
-- source: dbt-snowflake adapter statement shapes
commit
----
-- source: dbt-snowflake adapter statement shapes
create or replace transient table ANALYTICS.DBT_PROD.orders_snapshot as ( select *, md5(coalesce(cast(order_id as varchar), '')) as dbt_scd_id, current_timestamp() as dbt_updated_at, current_timestamp() as dbt_valid_from, null::timestamp as dbt_valid_to from ANALYTICS.DBT_PROD.stg_orders )
----
-- source: dbt-snowflake adapter statement shapes
merge into ANALYTICS.DBT_PROD.orders_snapshot as DBT_INTERNAL_DEST using ANALYTICS.DBT_PROD.orders_snapshot__dbt_tmp as DBT_INTERNAL_SOURCE on DBT_INTERNAL_SOURCE.dbt_scd_id = DBT_INTERNAL_DEST.dbt_scd_id when matched and DBT_INTERNAL_DEST.dbt_valid_to is null and DBT_INTERNAL_SOURCE.dbt_change_type in ('update', 'delete') then update set dbt_valid_to = DBT_INTERNAL_SOURCE.dbt_valid_to when not matched and DBT_INTERNAL_SOURCE.dbt_change_type = 'insert' then insert ("ORDER_ID", "DBT_SCD_ID") values ("ORDER_ID", "DBT_SCD_ID")
----
-- source: dbt-snowflake adapter statement shapes
create or replace function ANALYTICS.DBT_PROD.cents_to_dollars(cents number) returns number language sql as $$ cents / 100 $$
----
-- source: dbt-snowflake adapter statement shapes
alter view ANALYTICS.DBT_PROD.stg_orders set secure
----
-- source: dbt-snowflake adapter statement shapes
create or replace transient table ANALYTICS.DBT_PROD.orders__dbt_backup clone ANALYTICS.DBT_PROD.orders
----
-- source: sqlglot tests/dialects/test_snowflake.py
WITH t AS (SELECT PARSE_JSON('{"level1": {"level2": {"level3": "value"}}}') AS data) SELECT data:     level1  : level2 : level3::VARIANT FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM x ASOF JOIN y OFFSET MATCH_CONDITION (x.a > y.a)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM x ASOF JOIN y LIMIT MATCH_CONDITION (x.a > y.a)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT session
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_PART(EPOCH_MILLISECOND, CURRENT_TIMESTAMP()) AS a
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT GET(a, b)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT HASH_AGG(a, b, c, d)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT GREATEST(1, 2, 3, NULL)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT GREATEST_IGNORE_NULLS(1, 2, 3, NULL)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT LEAST(5, NULL, 7, 3)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT LEAST_IGNORE_NULLS(5, NULL, 7, 3)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MAX(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT COUNT(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MIN(amount)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MODE(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MODE(status) OVER (PARTITION BY region) FROM orders
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TAN(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT COS(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SINH(1.5)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MOD(x, y)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ROUND(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ROUND(123.456, -1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ROUND(123.456, 2, 'HALF_AWAY_FROM_ZERO')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT FLOOR(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT FLOOR(135.135, 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT FLOOR(x, -1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT PERCENTILE_CONT(0.25) WITHIN GROUP (ORDER BY salary) FROM employees
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT APPROX_TOP_K(col) FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT APPROX_TOP_K(category, 3) FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MINHASH(5, col)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MINHASH(5, col1, col2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MINHASH(5, *)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MINHASH_COMBINE(minhash_col)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT APPROXIMATE_SIMILARITY(minhash_col)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT APPROXIMATE_JACCARD_INDEX(minhash_col)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT APPROX_PERCENTILE_ACCUMULATE(col)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT APPROX_PERCENTILE_ESTIMATE(state, 0.5)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT APPROX_TOP_K_ACCUMULATE(col, 10)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT APPROX_TOP_K_COMBINE(state, 2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT APPROX_TOP_K_COMBINE(state)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT APPROX_TOP_K_ESTIMATE(state_column, 4)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT APPROX_TOP_K_ESTIMATE(state_column)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT APPROX_PERCENTILE_COMBINE(state_column)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EQUAL_NULL(1, 2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXP(1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT FACTORIAL(5)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BIT_LENGTH('abc')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BIT_LENGTH(x'A1B2')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITMAP_BIT_POSITION(10)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITMAP_BUCKET_NUMBER(32769)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITMAP_CONSTRUCT_AGG(value)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITMAP_CONSTRUCT_AGG(v) FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITMAP_COUNT(BITMAP_CONSTRUCT_AGG(value)) FROM TABLE(FLATTEN(INPUT => ARRAY_CONSTRUCT(1, 2, 3, 5)))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_MAX([1, 2, 3])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_MIN([1, 2, 3])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BOOLAND(1, -2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BOOLXOR(2, 0)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BOOLOR(1, 0)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_BOOLEAN('true')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_BOOLEAN(1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_VARIANT(123)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT IS_NULL_VALUE(GET_PATH(payload, 'field'))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RTRIMMED_LENGTH(' ABCD ')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT HEX_DECODE_STRING('48656C6C6F')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT HEX_ENCODE('Hello World')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT HEX_ENCODE('Hello World', 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT HEX_ENCODE('Hello World', 0)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT IFNULL(col1, col2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT NEXT_DAY('2025-10-15', 'FRIDAY')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT NVL2(col1, col2, col3)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT NVL(col1, col2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CHR(8364)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CHECK_JSON(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CHECK_JSON('{"key": "value"}')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CHECK_XML('<root><key attribute="attr">value</key></root>')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CHECK_XML('<root><key attribute="attr">value</key></root>', TRUE)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT COMPRESS('Hello World', 'ZLIB')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DECOMPRESS_BINARY('compressed_data', 'SNAPPY')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DECOMPRESS_STRING('compressed_data', 'ZSTD')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT LPAD('Hello', 10, '*')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT LPAD(tbl.bin_col, 10)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RPAD('Hello', 10, '*')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RPAD(tbl.bin_col, 10)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RPAD('test', 10, 'ab')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RPAD('data', 8)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RPAD('exact', 5, '*')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RPAD(TO_BINARY('Hi', 'UTF8'), 10, TO_BINARY('_', 'UTF8'))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SOUNDEX(column_name)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SOUNDEX_P123(column_name)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ABS(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ASIN(0.5)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ASINH(0.5)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ATAN(0.5)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ATAN2(0.5, 0.3)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ATANH(0.5)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CBRT(27.0)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT POW(2, 3)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT POW(2.5, 3.0)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SQUARE(2.5)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SIGN(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT COSH(1.5)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TANH(0.5)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TRANSLATE(column_name, 'abc', '123')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT UNICODE(column_name)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT WIDTH_BUCKET(col, 0, 100, 10)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SPLIT_PART('11.22.33', '.', 2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SPLIT('127.0.0.1', '.')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT PI()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DEGREES(PI() / 3)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DEGREES(1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RADIANS(180)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGR_VALX(y, x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGR_VALY(y, x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGR_AVGX(y, x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGR_AVGY(y, x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGR_COUNT(y, x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGR_INTERCEPT(y, x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGR_R2(y, x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGR_SXX(y, x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGR_SXY(y, x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGR_SYY(y, x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGR_SLOPE(y, x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT IS_ARRAY(PARSE_JSON('[1,2,3]'))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT IFF(x > 5, 10, 20)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT IFF(col IS NULL, 0, col)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT VAR_SAMP(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT GREATEST(1, 2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT GREATEST_IGNORE_NULLS(1, 2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT LEAST(1, 2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT LEAST_IGNORE_NULLS(1, 2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT VAR_POP(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RANDOM()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RANDOM(123)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RANDSTR(123, 456)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RANDSTR(123, RANDOM())
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT NORMAL(0, 1, RANDOM())
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RANDSTR(10, 123)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RANDSTR(10, RANDOM(123))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RANDSTR(10, RANDOM())
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BOOLNOT(0)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ZIPF(1, 10, 1234)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ZIPF(2, 100, RANDOM())
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT GROUPING_ID(a, b) AS g_id FROM x GROUP BY ROLLUP (a, b)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT XMLGET(object_col, 'level2')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT XMLGET(object_col, 'level3', 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT {*} FROM my_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT {my_table.*} FROM my_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT {* ILIKE 'col1%'} FROM my_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT {* EXCLUDE (col1)} FROM my_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT {* EXCLUDE (col1, col2)} FROM my_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT a, b, COUNT(*) FROM x GROUP BY ALL LIMIT 100
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT value FROM t, LATERAL SPLIT_TO_TABLE(t.a, '.')
----
-- source: sqlglot tests/dialects/test_snowflake.py
INSERT INTO test VALUES (x'48FAF43B0AFCEF9B63EE3A93EE2AC2')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT STAR(tbl, exclude := [foo])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CAST([1, 2, 3] AS VECTOR(FLOAT, 3))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT VECTOR_COSINE_SIMILARITY(a, b)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT VECTOR_INNER_PRODUCT(a, b)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT VECTOR_L1_DISTANCE(a, b)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT VECTOR_L2_DISTANCE(a, b)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CONNECT_BY_ROOT test AS test_column_alias
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE table1 CLUSTER BY (name1, name2, name3)
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE table1 CLUSTER BY (name)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT rename, replace
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIMEADD(HOUR, 2, CAST('09:05:03' AS TIME))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CAST(OBJECT_CONSTRUCT('a', 1) AS MAP(VARCHAR, INT))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MAP_CAT(CAST(col AS MAP(VARCHAR, VARCHAR)), CAST(col AS MAP(VARCHAR, VARCHAR)))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MAP_CAT(CAST(m1 AS MAP(VARCHAR, INT)), CAST(m2 AS MAP(VARCHAR, INT)))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MAP_CAT(CAST(OBJECT_CONSTRUCT() AS MAP(VARCHAR, INT)), CAST(OBJECT_CONSTRUCT('a', 1) AS MAP(VARCHAR, INT)))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MAP_CONTAINS_KEY('k1', CAST(col AS MAP(VARCHAR, VARCHAR)))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MAP_DELETE(CAST(col AS MAP(VARCHAR, VARCHAR)), 'k1')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MAP_INSERT(CAST(col AS MAP(VARCHAR, VARCHAR)), 'b', '2')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MAP_KEYS(CAST(col AS MAP(VARCHAR, VARCHAR)))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MAP_PICK(CAST(col AS MAP(VARCHAR, VARCHAR)), 'a', 'c')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MAP_SIZE(CAST(col AS MAP(VARCHAR, VARCHAR)))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CAST(OBJECT_CONSTRUCT('a', 1) AS OBJECT(a CHAR NOT NULL))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CAST([1, 2, 3] AS ARRAY(INT))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CAST(obj AS OBJECT(x CHAR) RENAME FIELDS)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CAST(obj AS OBJECT(x CHAR, y VARCHAR) ADD FIELDS)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIMESTAMP(x) FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIMESTAMP_NTZ(x) FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIMESTAMP_LTZ(x) FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIMESTAMP_TZ(x) FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE authors ADD CONSTRAINT c1 UNIQUE (id, email)
----
-- source: sqlglot tests/dialects/test_snowflake.py
RM @parquet_stage
----
-- source: sqlglot tests/dialects/test_snowflake.py
REMOVE @parquet_stage
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIMESTAMP_FROM_PARTS(2024, 5, 9, 14, 30, 45)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIMESTAMP_FROM_PARTS(2024, 5, 9, 14, 30, 45, 123)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIMESTAMP_LTZ_FROM_PARTS(2013, 4, 5, 12, 00, 00)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIMESTAMP_TZ_FROM_PARTS(2013, 4, 5, 12, 00, 00)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIMESTAMP_TZ_FROM_PARTS(2013, 4, 5, 12, 00, 00, 0, 'America/Los_Angeles')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIMESTAMP_FROM_PARTS(CAST('2024-05-09' AS DATE), CAST('14:30:45' AS TIME))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIMESTAMP_NTZ_FROM_PARTS(TO_DATE('2013-04-05'), TO_TIME('12:00:00'))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIMESTAMP_NTZ_FROM_PARTS(2013, 4, 5, 12, 00, 00, 987654321)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_FROM_PARTS(1977, 8, 7)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT GET_PATH(v, 'attr[0].name') FROM vartab
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_ARRAY(CAST(x AS ARRAY))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_ARRAY(CAST(['test'] AS VARIANT))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_UNIQUE_AGG(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_UNIQUE_AGG(col) FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_UNIQUE_AGG(col) OVER (PARTITION BY grp) FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_AGG(col) FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_DISTINCT(col)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_APPEND([1, 2, 3], 4)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_CAT([1, 2], [3, 4])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_PREPEND([2, 3, 4], 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_REMOVE([1, 2, 3], 2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAYS_ZIP([1, 2, 3])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAYS_ZIP([1, 2, 3], ['a', 'b', 'c'], [10, 20, 30])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT AI_AGG(review, 'Summarize the reviews')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT AI_SUMMARIZE_AGG(review)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT AI_CLASSIFY('text', ['travel', 'cooking'])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT OBJECT_CONSTRUCT()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_ACCOUNT()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_ACCOUNT_NAME()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_AVAILABLE_ROLES()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_CLIENT()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_IP_ADDRESS()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_DATABASE()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_SCHEMAS()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_SECONDARY_ROLES()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_SESSION()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_STATEMENT()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_VERSION()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_TRANSACTION()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_WAREHOUSE()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_ORGANIZATION_USER()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_REGION()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_ROLE()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_ROLE_TYPE()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DAY(CURRENT_TIMESTAMP())
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DAYOFMONTH(CURRENT_TIMESTAMP())
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DAYOFYEAR(CURRENT_TIMESTAMP())
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MONTH(CURRENT_TIMESTAMP())
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT QUARTER(CURRENT_TIMESTAMP())
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT WEEK(CURRENT_TIMESTAMP())
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT WEEKISO(CURRENT_TIMESTAMP())
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT YEAR(CURRENT_TIMESTAMP())
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT YEAROFWEEK(CURRENT_TIMESTAMP())
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT YEAROFWEEKISO(CURRENT_TIMESTAMP())
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DAYOFWEEKISO('2024-01-15'::DATE)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT YEAROFWEEK('2024-12-31'::DATE)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT YEAROFWEEKISO('2024-12-31'::DATE)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT WEEKISO('2024-01-15'::DATE)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SUM(amount) FROM mytable GROUP BY ALL
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT STDDEV(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT STDDEV(x) OVER (PARTITION BY 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT STDDEV_POP(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT STDDEV_POP(x) OVER (PARTITION BY 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT STDDEV_SAMP(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT STDDEV_SAMP(x) OVER (PARTITION BY 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT KURTOSIS(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT KURTOSIS(x) OVER (PARTITION BY 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
WITH x AS (SELECT 1 AS foo) SELECT foo FROM IDENTIFIER('x')
----
-- source: sqlglot tests/dialects/test_snowflake.py
WITH x AS (SELECT 1 AS foo) SELECT IDENTIFIER('foo') FROM x
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT IDENTIFIER($my_function_name)()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT IDENTIFIER('speed_of_light')()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT IDENTIFIER('my_func')(1, 2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CAST('2021-01-01' AS DATE) + INTERVAL '1 DAY'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT HLL(*)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT HLL(a)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT HLL(DISTINCT t.a)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT HLL(a, b, c)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT HLL(DISTINCT a, b, c)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGEXP_LIKE(a, b, c)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE foo (bar DOUBLE AUTOINCREMENT START 0 INCREMENT 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
COMMENT IF EXISTS ON TABLE foo IS 'bar'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CONVERT_TIMEZONE('UTC', 'America/Los_Angeles', col)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_ORGANIZATION_NAME()
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE a SWAP WITH b
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MATCH_CONDITION
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT OBJECT_AGG(key, value) FROM tbl
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_CHAR(CAST('12:05:05' AS TIME))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TRIM(COALESCE(TO_CHAR(CAST(c AS TIME)), '')) FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT GET_PATH(PARSE_JSON(foo), 'bar')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT PARSE_IP('192.168.1.1', 'INET')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT PARSE_IP('192.168.1.1', 'INET', 0)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT GET_PATH(foo, 'bar')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT a, exclude, b FROM xxx
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_SORT(x, TRUE, FALSE)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_SORT(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_SORT(x, FALSE)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_SORT(x, foo, TRUE)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BOOLXOR_AGG(col) FROM tbl
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT PERCENTILE_DISC(0.9) WITHIN GROUP (ORDER BY col) OVER (PARTITION BY category)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT STRTOK('a$b/cg', '$/.')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT STRTOK('ab')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT AI_CLASSIFY('text', ['travel', 'cooking'], OBJECT_CONSTRUCT('output_mode', 'multi'))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM table AT (TIMESTAMP => '2024-07-24') UNPIVOT(a FOR b IN (c)) AS pivot_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM quarterly_sales PIVOT(SUM(amount) FOR quarter IN ('2023_Q1', '2023_Q2', '2023_Q3', '2023_Q4', '2024_Q1') DEFAULT ON NULL (0)) ORDER BY empid
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM quarterly_sales PIVOT(SUM(amount) FOR quarter IN (SELECT DISTINCT quarter FROM ad_campaign_types_by_quarter WHERE television = TRUE ORDER BY quarter)) ORDER BY empid
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM quarterly_sales PIVOT(SUM(amount) FOR quarter IN (ANY ORDER BY quarter)) ORDER BY empid
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM quarterly_sales PIVOT(SUM(amount) FOR quarter IN (ANY)) ORDER BY empid
----
-- source: sqlglot tests/dialects/test_snowflake.py
MERGE INTO my_db AS ids USING (SELECT new_id FROM my_model WHERE NOT col IS NULL) AS new_ids ON ids.type = new_ids.type AND ids.source = new_ids.source WHEN NOT MATCHED THEN INSERT VALUES (new_ids.new_id)
----
-- source: sqlglot tests/dialects/test_snowflake.py
INSERT OVERWRITE TABLE t SELECT 1
----
-- source: sqlglot tests/dialects/test_snowflake.py
DESCRIBE TABLE "SNOWFLAKE_SAMPLE_DATA"."TPCDS_SF100TCL"."WEB_SITE" type=stage
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM DATA AS DATA_L ASOF JOIN DATA AS DATA_R MATCH_CONDITION (DATA_L.VAL > DATA_R.VAL) ON DATA_L.ID = DATA_R.ID
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIMESTAMP('2025-01-16T14:45:30.123+0500', 'yyyy-mm-DDThh24:mi:ss.ff9tzhtzm')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * REPLACE (CAST(col AS TEXT) AS scol) FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 1 put
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 1 get
----
-- source: sqlglot tests/dialects/test_snowflake.py
WITH t (SELECT 1 AS c) SELECT c FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM s WHERE c NOT IN (1, 2, 3)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM s WHERE c NOT IN (SELECT * FROM t)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM t1 INNER JOIN t2 USING (t1.col)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT a:from::STRING, a:from || ' test'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT a:select
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT GET_PATH(PARSE_JSON('{"y": [{"z": 1}]}'), 'y[0]:z')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT p FROM t WHERE p:val NOT IN ('2')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT PARSE_JSON('{"x": "hello"}'):x LIKE 'hello'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT data:x LIKE 'hello' FROM some_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SUM({ fn CONVERT(123, SQL_DOUBLE) })
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SUM({ fn CONVERT(123, SQL_VARCHAR) })
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIMESTAMPFROMPARTS(d, t)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT v:attr[0].name FROM vartab
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT v:"fruit" FROM vartab
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT PARSE_JSON('{"food":{"fruit":"banana"}}'):food.fruit::VARCHAR
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM t, UNNEST(x) WITH ORDINALITY
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE foo (ID INT COMMENT $$some comment$$)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT state, city, SUM(retail_price * quantity) AS gross_revenue FROM sales GROUP BY ALL
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM foo window
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RLIKE(a, $$regular expression with \ characters: \d{2}-\d{3}-\d{4}$$, 'i') FROM log_source
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT $$a ' \ \t \x21 z $ $$
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT $$a\$b$$
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT $$a\$$
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT {'test': 'best'}::VARIANT
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT {fn DAYNAME('2022-5-13')}
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT {fn LOG(5)}
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT {fn CEILING(5.3)}
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CEIL(3.14)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CEIL(3.14, 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE TEMPORARY TABLE x (y NUMBER IDENTITY(0, 1))
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TEMPORARY TABLE x (y NUMBER AUTOINCREMENT(0, 1))
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE TABLE x (y NUMBER(38, 0) NOT NULL AUTOINCREMENT START 1 INCREMENT 1 ORDER)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE TABLE x (y NUMBER(38, 0) NOT NULL AUTOINCREMENT START 1 INCREMENT 1 NOORDER)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE x (y NUMBER IDENTITY START 0 INCREMENT 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE foo ADD COLUMN id INT identity(1, 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE x (y INT AUTOINCREMENT START 10)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE x (y INT AUTOINCREMENT INCREMENT 2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE x (y INT AUTOINCREMENT ORDER)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE x (y INT AUTOINCREMENT NOORDER)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE x (y INT AUTOINCREMENT START 10 NOORDER)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE x (y INT AUTOINCREMENT INCREMENT 2 ORDER)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE x (y INT AUTOINCREMENT INCREMENT 2 START 10)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE x (y INT AUTOINCREMENT(0, 1) ORDER)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DAYOFWEEK('2016-01-02T23:39:20.123-07:00'::TIMESTAMP)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM xxx WHERE col ilike '%Don''t%'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * EXCLUDE a, b FROM xxx
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * RENAME a AS b, c AS d FROM xxx
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM xxx, yyy, zzz,
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM xxx, yyy, zzz, WHERE foo = bar
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM xxx, yyy, zzz
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT LTRIM(RTRIM(col)) FROM t1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT value['x'] AS x FROM TABLE(FLATTEN(INPUT => [OBJECT_CONSTRUCT('x', 'x')])) AS _t0(seq, key, path, index, value, this)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT value['x'] AS x, value['y'] AS y, value['z'] AS z FROM TABLE(FLATTEN(INPUT => [OBJECT_CONSTRUCT('x', 1, 'y', 2, 'z', 3)])) AS _t0(seq, key, path, index, value, this)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT u1['x'] AS x, u2['y'] AS y FROM TABLE(FLATTEN(INPUT => [OBJECT_CONSTRUCT('x', 1)])) AS _t0(seq, key, path, index, u1, this) CROSS JOIN TABLE(FLATTEN(INPUT => [OBJECT_CONSTRUCT('y', 2)])) AS _t1(seq, key, path, index, u2, this)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT t.id, value['name'] AS name, value['age'] AS age FROM t CROSS JOIN TABLE(FLATTEN(INPUT => [OBJECT_CONSTRUCT('name', 'John', 'age', 30)])) AS _t0(seq, key, path, index, value, this)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT value FROM TABLE(FLATTEN(INPUT => [OBJECT_CONSTRUCT('x', 1)])) AS _t0(seq, key, path, index, value, this)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT t.col1, value['field1'] AS field1, other_col, value['field2'] AS field2 FROM t CROSS JOIN TABLE(FLATTEN(INPUT => [OBJECT_CONSTRUCT('field1', 'a', 'field2', 'b')])) AS _t0(seq, key, path, index, value, this)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM (SELECT value['x'] AS x FROM TABLE(FLATTEN(INPUT => [OBJECT_CONSTRUCT('x', 'value')])) AS _t0(seq, key, path, index, value, this))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT value FROM TABLE(FLATTEN(INPUT => [1, 2, 3])) AS _t0(seq, key, path, index, value, this)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM t1 AS t1 CROSS JOIN t2 AS t2 LEFT JOIN t3 AS t3 ON t1.a = t3.i
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT value['x'] AS x, yval, zval FROM TABLE(FLATTEN(INPUT => [OBJECT_CONSTRUCT('x', 'x', 'y', ['y1', 'y2', 'y3'], 'z', ['z1', 'z2', 'z3'])])) AS _t0(seq, key, path, index, value, this) CROSS JOIN TABLE(FLATTEN(INPUT => value['y'])) AS _t1(seq, key, path, index, yval, this) CROSS JOIN TABLE(FLATTEN(INPUT => value['z'])) AS _t2(seq, key, path, index, zval, this)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAYS_OVERLAP(col1, col2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_INTERSECTION([1, 2], [2, 3])
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE test_table (id NUMERIC NOT NULL AUTOINCREMENT)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIMESTAMP('2025-01-16 14:45:30.123', 'yyyy-mm-DD hh24:mi:ss.ff6')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIME_FROM_PARTS(12, 34, 56)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIME_FROM_PARTS(12, 34, 56, 987654321)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIME_FROM_PARTS(0, 100, 0)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIMESTAMPNTZFROMPARTS(2013, 4, 5, 12, 00, 00)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIMESTAMP_NTZ_FROM_PARTS(2013, 4, 5, 12, 00, 00)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIMESTAMP_FROM_PARTS(TO_DATE('2023-06-15'), TO_TIME('14:30:45'))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIMESTAMP_NTZ_FROM_PARTS(TO_DATE('2023-06-15'), TO_TIME('14:30:45'))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIMESTAMP_LTZ_FROM_PARTS(2023, 6, 15, 14, 30, 45)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIMESTAMP_TZ_FROM_PARTS(2023, 6, 15, 14, 30, 45, 0, 'America/Los_Angeles')
----
-- source: sqlglot tests/dialects/test_snowflake.py
WITH vartab(v) AS (select parse_json('[{"attr": [{"name": "banana"}]}]')) SELECT GET_PATH(v, '[0].attr[0].name') FROM vartab
----
-- source: sqlglot tests/dialects/test_snowflake.py
WITH vartab(v) AS (select parse_json('{"attr": [{"name": "banana"}]}')) SELECT GET_PATH(v, 'attr[0].name') FROM vartab
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT PARSE_JSON('{"fruit":"banana"}'):fruit
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_ARRAY(['test'])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT { 'Manitoba': 'Winnipeg', 'foo': 'bar' } AS province_capital
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT COLLATE('B', 'und:ci')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT To_BOOLEAN('T')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT id FROM t START WITH (parent_id IS NULL) CONNECT BY PRIOR id = parent_id
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT id FROM t START WITH (x) CONNECT BY PRIOR id = parent_id
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT INSERT(a, 0, 0, 'b')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_GENERATE_RANGE(-5, -25, -10)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_GENERATE_RANGE(5, 1, -1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_PART('year', TIMESTAMP '2020-01-01')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM (VALUES (0) foo(bar))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT i, p, o FROM qt QUALIFY ROW_NUMBER() OVER (PARTITION BY p ORDER BY o) = 1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT NTH_VALUE(a, 2) FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT NTH_VALUE(is_deleted, 2) FROM FIRST IGNORE NULLS OVER (PARTITION BY id) AS nth_is_deleted FROM my_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT NTH_VALUE(is_deleted, 2) FROM LAST RESPECT NULLS OVER (PARTITION BY id) AS nth_is_deleted FROM my_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT NTH_VALUE(is_deleted, 2) OVER (PARTITION BY id) AS nth_is_deleted FROM my_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT NTH_VALUE(is_deleted, 2) OVER (PARTITION BY id ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING) AS nth_is_deleted FROM my_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT LEAD(is_deleted, 2, -10) RESPECT NULLS OVER (PARTITION BY id) AS nth_is_deleted FROM my_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT LEAD(is_deleted, 2) OVER (PARTITION BY id) AS nth_is_deleted FROM my_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT LAG(amount) OVER (ORDER BY seq) AS basic_lag
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT LAG(amount, 2) IGNORE NULLS OVER (PARTITION BY category ORDER BY seq) AS lag_offset_ignore_nulls
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT LAG(amount, 2, -777) RESPECT NULLS OVER (PARTITION BY category ORDER BY seq ASC) AS lag_full_ignore_nulls
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BOOLOR_AGG(c1), BOOLOR_AGG(c2) FROM test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BOOLAND_AGG(c1), BOOLAND_AGG(c2) FROM test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BOOLXOR_AGG(c1) FROM test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT COUNT_IF(x > 1) FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT PARSE_JSON('{"a": {"b c": "foo"}}'):a:"b c"
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT a FROM test WHERE a = 1 GROUP BY a HAVING a = 2 QUALIFY z ORDER BY a LIMIT 10
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT a FROM test AS t QUALIFY ROW_NUMBER() OVER (PARTITION BY a ORDER BY Z) = 1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIMESTAMP(col, 'DD-MM-YYYY HH12:MI:SS') FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIMESTAMP(1659981729)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIMESTAMP(1659981729000, 3)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIMESTAMP(16599817290000, 4)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIMESTAMP('1659981729')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIMESTAMP(1659981729000000000, 9)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIMESTAMP('2013-04-05 01:02:03')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT IFF(TRUE, 'true', 'false')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT fname, lname, age FROM person ORDER BY age DESC NULLS FIRST, fname ASC NULLS LAST, lname
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_AGG(DISTINCT a)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_AGG(col) WITHIN GROUP (ORDER BY sort_col)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_AGG(DISTINCT col) WITHIN GROUP (ORDER BY col DESC)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_TO_STRING(x, '')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_TO_STRING(x, NULL)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_TO_STRING([], ',')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM a INTERSECT ALL SELECT * FROM b
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM a EXCEPT ALL SELECT * FROM b
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_UNION_AGG(a)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT $$a$$
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT a RLIKE b
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT a NOT RLIKE b
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RLIKE(a, b)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT RLIKE(a, b, 'i')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT a FROM test pivot
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT a FROM test unpivot
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BOOLXOR(2, 0.3)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT OBJECT_INSERT(OBJECT_INSERT(OBJECT_INSERT(OBJECT_CONSTRUCT('key5', 'value5'), 'key1', 5), 'key2', 2.2), 'key3', 'value3')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT OBJECT_INSERT(OBJECT_INSERT(OBJECT_INSERT(OBJECT_CONSTRUCT(), 'key1', 5), 'key2', 2.2), 'key3', 'value3')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_CONSTRUCT('foo')::VARIANT[0]
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CONVERT_TIMEZONE('America/New_York', '2024-08-06 09:10:00.000')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CONVERT_TIMEZONE('America/Los_Angeles', 'America/New_York', '2024-08-06 09:10:00.000')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT UUID_STRING(), UUID_STRING('fe971b24-9572-4005-b22f-351e9c09274d', 'foo')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TRY_TO_TIMESTAMP('2024-01-15 12:30:00.000')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TRY_TO_TIMESTAMP('invalid')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TRY_TO_TIMESTAMP('04/05/2013 01:02:03', 'mm/DD/yyyy hh24:mi:ss')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITNOT(a)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BIT_NOT(a)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITNOT(-1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITAND(a, b)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITAND(a, b, 'LEFT')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BIT_AND(a, b)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BIT_AND(a, b, 'LEFT')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITOR(a, b)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITOR(a, b, 'LEFT')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BIT_OR(a, b)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BIT_OR(a, b, 'RIGHT')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITXOR(a, b)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITXOR(a, b, 'LEFT')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BIT_XOR(a, b)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BIT_XOR(a, b, 'LEFT')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITOR(BITSHIFTLEFT(5, 16), BITSHIFTLEFT(3, 8))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITAND(BITSHIFTLEFT(255, 4), BITSHIFTLEFT(15, 2))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITSHIFTLEFT(255, 4)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITSHIFTRIGHT(255, 4)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITSHIFTLEFT(X'002A'::BINARY, 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BITSHIFTRIGHT(X'002A'::BINARY, 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE t (id INT PRIMARY KEY AUTOINCREMENT)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT HEX_DECODE_BINARY('65')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_PART(WEEKISO, CAST('2013-12-25' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_PART(YEAROFWEEK, CAST('2026-01-06' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_PART(YEAROFWEEKISO, CAST('2026-01-06' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_PART(NANOSECOND, CAST('2026-01-06 11:45:00.123456789' AS TIMESTAMPNTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(YEAR FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(QUARTER FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(MONTH FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(WEEK FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(WEEKISO FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(DAY FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(DAYOFMONTH FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(DAYOFWEEK FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(DAYOFWEEKISO FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(DAYOFYEAR FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(YEAROFWEEK FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(YEAROFWEEKISO FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(HOUR FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(MINUTE FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(SECOND FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(NANOSECOND FROM CAST('2026-01-06 11:45:00.123456789' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(EPOCH_SECOND FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(EPOCH_MILLISECOND FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(EPOCH_MICROSECOND FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(EPOCH_NANOSECOND FROM CAST('2026-01-06 11:45:00' AS TIMESTAMP_NTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(YEAR FROM CAST('2026-01-06' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(QUARTER FROM CAST('2026-01-06' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(MONTH FROM CAST('2026-01-06' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(WEEK FROM CAST('2026-01-06' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(WEEKISO FROM CAST('2026-01-06' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(DAY FROM CAST('2026-01-06' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(DAYOFMONTH FROM CAST('2026-01-06' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(DAYOFWEEK FROM CAST('2026-01-06' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(DAYOFWEEKISO FROM CAST('2026-01-06' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(DAYOFYEAR FROM CAST('2026-01-06' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(YEAROFWEEK FROM CAST('2026-01-06' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(YEAROFWEEKISO FROM CAST('2026-01-06' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(HOUR FROM CAST('11:45:00.123456789' AS TIME))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(MINUTE FROM CAST('11:45:00.123456789' AS TIME))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT(SECOND FROM CAST('11:45:00.123456789' AS TIME))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ST_MAKEPOINT(10, 20)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ST_DISTANCE(a, b)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_PART(WEEKDAY_ISO, foo)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_PART(DAYOFWEEK_ISO, foo)
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE foo ADD col1 VARCHAR(512), col2 VARCHAR(512)
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE foo ADD col1 VARCHAR NOT NULL TAG (key1='value_1'), col2 VARCHAR NOT NULL TAG (key2='value_2')
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE foo ADD IF NOT EXISTS col1 INT, col2 INT
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE foo ADD IF NOT EXISTS col1 INT, IF NOT EXISTS col2 INT
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE foo ADD col1 INT, IF NOT EXISTS col2 INT
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE IF EXISTS foo ADD IF NOT EXISTS col1 INT
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ADD_MONTHS('2023-01-31', 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ADD_MONTHS('2023-01-31'::date, 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ADD_MONTHS('2023-01-31'::timestamptz, 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ADD_MONTHS('2016-05-15'::DATE, 2.7)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ADD_MONTHS('2016-05-15'::DATE, -2.3)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ADD_MONTHS('2016-05-15'::DATE, 3.2::DECIMAL(10,2))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ADD_MONTHS('2016-02-29'::DATE, 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ADD_MONTHS('2016-05-31'::DATE, 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ADD_MONTHS('2016-05-31'::DATE, -1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ADD_MONTHS('2016-05-15'::DATE, 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ADD_MONTHS(NULL::DATE, 2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ADD_MONTHS('2016-05-15'::DATE, NULL)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ADD_MONTHS('2016-05-15'::DATE, 0)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT HOUR(CAST('08:50:57' AS TIME))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MINUTE(CAST('08:50:57' AS TIME))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SECOND(CAST('08:50:57' AS TIME))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT HOUR(CAST('2024-05-09 08:50:57' AS TIMESTAMP))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MONTHNAME(CAST('2024-05-09' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DAYNAME(TO_DATE('2025-01-15'))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DAYNAME(TO_TIMESTAMP('2025-02-28 10:30:45'))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MONTHNAME(TO_DATE('2025-01-15'))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MONTHNAME(TO_TIMESTAMP('2025-02-28 10:30:45'))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT PREVIOUS_DAY(CAST('2024-05-09' AS DATE), 'MONDAY')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIME_FROM_PARTS(14, 30, 45)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIME_FROM_PARTS(14, 30, 45, 123)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MONTHS_BETWEEN(CAST('2019-03-15' AS DATE), CAST('2019-02-15' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MONTHS_BETWEEN(CAST('2019-03-01 02:00:00' AS TIMESTAMP), CAST('2019-02-15 01:00:00' AS TIMESTAMP))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIME_SLICE(CAST('2024-05-09 08:50:57.891' AS TIMESTAMP), 15, 'MINUTE')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIME_SLICE(CAST('2024-05-09' AS DATE), 1, 'DAY')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIME_SLICE(CAST('2024-05-09 08:50:57.891' AS TIMESTAMP), 1, 'HOUR', 'start')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIME_SLICE(TIMESTAMP '2024-03-15 14:37:42', 1, 'HOUR')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIME_SLICE(TIMESTAMP '2024-03-15 14:37:42', 1, 'HOUR', 'END')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIME_SLICE(DATE '2024-03-15', 1, 'DAY')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIME_SLICE(DATE '2024-03-15', 1, 'DAY', 'END')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIME_SLICE(TIMESTAMP '2024-03-15 14:37:42', 15, 'MINUTE')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIME_SLICE(TIMESTAMP '2024-03-15 14:37:42', 1, 'QUARTER')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TIME_SLICE(DATE '2024-03-15', 1, 'WEEK', 'END')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * EXCLUDE foo RENAME bar AS baz FROM tbl
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT LIKE(col, 'pattern')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ILIKE(col, 'pattern')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT LIKE(col, 'pattern', '\\')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ILIKE(col, 'pattern', '\\')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT LIKE(col, 'pattern', '!')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ILIKE(col, 'pattern', '!')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BASE64_ENCODE('Hello World')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BASE64_ENCODE(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BASE64_ENCODE(x, 76)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BASE64_ENCODE(x, 76, '+/=')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BASE64_DECODE_STRING('U25vd2ZsYWtl')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BASE64_DECODE_STRING('U25vd2ZsYWtl', '-_+')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BASE64_DECODE_BINARY(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT BASE64_DECODE_BINARY(x, '-_+')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TRY_HEX_DECODE_BINARY('48656C6C6F')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TRY_HEX_DECODE_STRING('48656C6C6F')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_CONTAINS(CAST('1' AS VARIANT), ['1'])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_CONTAINS(CAST(CAST('2020-10-10' AS DATE) AS VARIANT), [CAST('2020-10-10' AS DATE)])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_CONTAINS(1, [1])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_CONTAINS(x, [1, NULL, 3])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_DISTINCT(['A', 'B', 'A'])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_DISTINCT(['A', NULL, 'B', NULL])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_DISTINCT([1, 2, 2, 3, 1])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT x'ABCD'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SET a = 1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_TIME(4)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_TIME
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_FROM_PARTS(2026, 1, 100)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_FROM_PARTS(2026, 14, 32)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_FROM_PARTS(2026, 0, 0)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_FROM_PARTS(2026, -14, -32)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_FROM_PARTS(2024, 1, 60)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_FROM_PARTS(2026, NULL, 100)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_FROM_PARTS(2024 + 2, 1 + 2, 2 + 3)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_FROM_PARTS(year, month, date)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CURRENT_SCHEMA()
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 1 WHERE 'abc' ILIKE ANY('%a%')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 1 WHERE 'abc' LIKE ALL ('%a%')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 'he%lo' LIKE ANY ('he#%lo', 'hello') ESCAPE '#'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 'he%lo' LIKE ALL ('he#%lo', 'he#%lo2') ESCAPE '#'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 'he%lo' ILIKE ANY ('he#%lo', 'hello') ESCAPE '#'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 1 WHERE 'he%lo' LIKE ANY ('he#%lo', 'hello') ESCAPE '#' AND x = 1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 1 WHERE 'he%lo' LIKE ALL ('he#%lo', 'he#%lo2') ESCAPE '#' OR x = 1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM t UNPIVOT(a FOR b IN (c, d)) UNPIVOT(e FOR f IN (g, h))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM t PIVOT(SUM(v) FOR c IN ('a' AS a)) UNPIVOT(x FOR y IN (a))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT FIRST_VALUE(TABLE1.COLUMN1) OVER (PARTITION BY RANDOM_COLUMN1, RANDOM_COLUMN2 ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) AS MY_ALIAS FROM TABLE1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT FIRST_VALUE(TABLE1.COLUMN1 RESPECT NULLS) OVER (PARTITION BY RANDOM_COLUMN1, RANDOM_COLUMN2 ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) AS MY_ALIAS FROM TABLE1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT FIRST_VALUE(TABLE1.COLUMN1) RESPECT NULLS OVER (PARTITION BY RANDOM_COLUMN1, RANDOM_COLUMN2 ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) AS MY_ALIAS FROM TABLE1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT FIRST_VALUE(TABLE1.COLUMN1 IGNORE NULLS) OVER (PARTITION BY RANDOM_COLUMN1, RANDOM_COLUMN2 ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) AS MY_ALIAS FROM TABLE1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT FIRST_VALUE(TABLE1.COLUMN1) IGNORE NULLS OVER (PARTITION BY RANDOM_COLUMN1, RANDOM_COLUMN2 ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) AS MY_ALIAS FROM TABLE1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM @"mystage"
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM @"myschema"."mystage"/file.gz
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM @"my_DB"."schEMA1".mystage/file.gz
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT metadata$filename FROM @s1/
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM @~
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM @~/some/path/to/file.csv
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM @mystage
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM '@mystage'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM @namespace.mystage/path/to/file.json.gz
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM @namespace.%table_name/path/to/file.json.gz
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT $1, $2, metadata$filename FROM @mystage (PATTERN => '.*data-100.*')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM '@external/location' (FILE_FORMAT => 'path.to.csv')
----
-- source: sqlglot tests/dialects/test_snowflake.py
PUT file:///dir/tmp.csv @%table
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM (SELECT a FROM @foo)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM (SELECT * FROM '@external/location' (FILE_FORMAT => 'path.to.csv'))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM @foo/bar (FILE_FORMAT => ds_sandbox.test.my_csv_format, PATTERN => 'test') AS bla
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT t.$1, t.$2 FROM @mystage1 (FILE_FORMAT => 'myformat', PATTERN => '.*data.*[.]csv.gz') AS t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT parse_json($1):a.b FROM @mystage2/data1.json.gz
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM @mystage t (c1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM @foo/bar (PATTERN => 'test', FILE_FORMAT => ds_sandbox.test.my_csv_format) AS bla
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM @test.public.thing/location/somefile.csv( FILE_FORMAT => 'fmt' )
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM testtable TABLESAMPLE BERNOULLI (20.3)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM testtable TABLESAMPLE SYSTEM (3) SEED (82)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT a FROM test PIVOT(SUM(x) FOR y IN ('z', 'q')) AS x TABLESAMPLE BERNOULLI (0.1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT i, j FROM table1 AS t1 INNER JOIN table2 AS t2 TABLESAMPLE BERNOULLI (50) WHERE t2.j = t1.i
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM (SELECT * FROM t1 JOIN t2 ON t1.a = t2.c) TABLESAMPLE BERNOULLI (1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM testtable TABLESAMPLE (10 ROWS)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM testtable TABLESAMPLE (100)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM testtable SAMPLE (10)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM testtable SAMPLE ROW (0)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT a FROM test SAMPLE BLOCK (0.5) SEED (42)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT user_id, value FROM table_name SAMPLE BERNOULLI ($s) SEED (0)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM test AS _tmp TABLESAMPLE (5)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT i, j
                FROM
                     table1 AS t1 SAMPLE (25)     -- 25% of rows in table1
                         INNER JOIN
                     table2 AS t2 SAMPLE (50)     -- 50% of rows in table2
                WHERE t2.j = t1.i
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM testtable SAMPLE BLOCK (0.012) REPEATABLE (99992)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM (SELECT * FROM t1 join t2 on t1.a = t2.c) SAMPLE (1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CAST('12:00:00' AS TIME)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_PART(month, a)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT a::TIMESTAMP_LTZ(9)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT a::TIMESTAMPLTZ
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT a::TIMESTAMP WITH LOCAL TIME ZONE
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT EXTRACT('month', a)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_PART('month', a)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_PART(month, a::DATETIME)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_PART(epoch_second, foo) as ddate from table_name
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_PART(epoch_milliseconds, foo) as ddate from table_name
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIME(x) FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIME('12:05:00')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIME('2024-01-15 14:30:00'::TIMESTAMP)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIME(CONVERT_TIMEZONE('UTC', 'US/Pacific', '2024-08-06 09:10:00.000')) AS pst_time
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIME('11.15.00', 'hh24.mi.ss')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIME('093000', 'HH24MISS')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TRY_TO_TIME('093000', 'HH24MISS')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TRY_TO_TIME('11.15.00')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TRY_TO_TIME('11.15.00', 'hh24.mi.ss')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_DATE('2019-02-28') + INTERVAL '1 day, 1 year'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CAST(a AS VARIANT)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CAST(a AS ARRAY)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT a::VARIANT
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT a::OBJECT
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT NEXT_DAY(CAST('2024-01-01' AS DATE), 'Monday')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT NEXT_DAY(CAST('2024-01-05' AS DATE), 'Friday')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT NEXT_DAY(CAST('2024-01-05' AS DATE), 'WE')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT NEXT_DAY(CAST('2024-01-01 10:30:45' AS TIMESTAMP), 'Friday')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT NEXT_DAY(CAST('2024-01-01' AS DATE), day_column)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT PREVIOUS_DAY(DATE '2024-01-15', 'Monday')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT PREVIOUS_DAY(DATE '2024-01-15', 'Fr')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT PREVIOUS_DAY(TIMESTAMP '2024-01-15 10:30:45', 'Monday')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT PREVIOUS_DAY(DATE '2024-01-15', day_column)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM my_table AT (STATEMENT => $query_id_var)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM my_table AT (OFFSET => -60 * 5)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM my_table BEFORE (STATEMENT => $query_id_var)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM my_table BEFORE (OFFSET => -60 * 5)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE SCHEMA restored_schema CLONE my_schema AT (OFFSET => -3600)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE restored_table CLONE my_table AT (TIMESTAMP => CAST('Sat, 09 May 2015 01:01:00 +0300' AS TIMESTAMPTZ))
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE DATABASE restored_db CLONE my_db BEFORE (STATEMENT => '8e5d0ca9-005e-44e6-b858-a8f5b37c5726')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM my_table AT (TIMESTAMP => TO_TIMESTAMP(1432669154242, 3))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM my_table AT (OFFSET => -60 * 5) AS T WHERE T.flag = 'valid'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM my_table AT (STATEMENT => '8e5d0ca9-005e-44e6-b858-a8f5b37c5726')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM my_table BEFORE (STATEMENT => '8e5d0ca9-005e-44e6-b858-a8f5b37c5726')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM my_table AT (TIMESTAMP => 'Fri, 01 May 2015 16:20:00 -0700'::timestamp)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM my_table AT(TIMESTAMP => 'Fri, 01 May 2015 16:20:00 -0700'::timestamp_tz)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM my_table BEFORE (TIMESTAMP => 'Fri, 01 May 2015 16:20:00 -0700'::timestamp_tz);
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT oldt.* , newt.*
            FROM my_table BEFORE(STATEMENT => '8e5d0ca9-005e-44e6-b858-a8f5b37c5726') AS oldt
            FULL OUTER JOIN my_table AT(STATEMENT => '8e5d0ca9-005e-44e6-b858-a8f5b37c5726') AS newt
            ON oldt.id = newt.id
            WHERE oldt.id IS NULL OR newt.id IS NULL;
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE TABLE foo COPY GRANTS USING TEMPLATE (SELECT 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
USE SECONDARY ROLES ALL
----
-- source: sqlglot tests/dialects/test_snowflake.py
USE SECONDARY ROLES NONE
----
-- source: sqlglot tests/dialects/test_snowflake.py
USE SECONDARY ROLES a, b, c
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE SECURE VIEW table1 AS (SELECT a FROM table2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE VIEW foo (uid) COPY GRANTS AS (SELECT 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE geospatial_table (id INT, g GEOGRAPHY)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE t (id INT) CHANGE_TRACKING=TRUE
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE t CHANGE_TRACKING=TRUE DATA_RETENTION_TIME_IN_DAYS=1 (id INT)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE DATABASE mytestdb_clone CLONE mytestdb
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE SCHEMA mytestschema_clone CLONE testschema
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE IDENTIFIER('foo') (COLUMN1 VARCHAR, COLUMN2 VARCHAR)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE IDENTIFIER($foo) (col1 VARCHAR, col2 VARCHAR)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TAG cost_center ALLOWED_VALUES 'a', 'b'
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE STAGE stage1 FILE_FORMAT='format1'
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE STAGE stage1 FILE_FORMAT=(FORMAT_NAME=stage1.format1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE STAGE stage1 FILE_FORMAT=(FORMAT_NAME='stage1.format1')
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE STAGE stage1 FILE_FORMAT=schema1.format1
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE STAGE s1 URL='s3://bucket-123' FILE_FORMAT=(TYPE='JSON') CREDENTIALS=(aws_key_id='test' aws_secret_key='test')
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE DYNAMIC TABLE product (pre_tax_profit, taxes, after_tax_profit) TARGET_LAG='20 minutes' WAREHOUSE=mywh AS SELECT revenue - cost, (revenue - cost) * tax_rate, (revenue - cost) * (1.0 - tax_rate) FROM staging_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE DYNAMIC TABLE dt TARGET_LAG='1 minute' WAREHOUSE=my_wh (id) AS SELECT * FROM bla
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE db_name.schmaName.tblName ADD COLUMN_1 VARCHAR NOT NULL TAG (key1='value_1')
----
-- source: sqlglot tests/dialects/test_snowflake.py
DROP FUNCTION my_udf (OBJECT(city VARCHAR, zipcode DECIMAL(38, 0), val ARRAY(BOOLEAN)))
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE orders_clone_restore CLONE orders AT (TIMESTAMP => TO_TIMESTAMP_TZ('04/05/2013 01:02:03', 'mm/dd/yyyy hh24:mi:ss'))
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE orders_clone_restore CLONE orders BEFORE (STATEMENT => '8e5d0ca9-005e-44e6-b858-a8f5b37c5726')
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE SCHEMA mytestschema_clone_restore CLONE testschema BEFORE (TIMESTAMP => TO_TIMESTAMP(40 * 365 * 86400))
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE TABLE EXAMPLE_DB.DEMO.USERS (ID DECIMAL(38, 0) NOT NULL, PRIMARY KEY (ID), FOREIGN KEY (CITY_CODE) REFERENCES EXAMPLE_DB.DEMO.CITIES (CITY_CODE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE t (a ARRAY(INT), b ARRAY(ARRAY(INT)), c OBJECT(x INT), d MAP(VARCHAR, INT))
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE ICEBERG TABLE my_iceberg_table (amount ARRAY(INT)) CATALOG='SNOWFLAKE' EXTERNAL_VOLUME='my_external_volume' BASE_LOCATION='my/relative/path/from/extvol'
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE FUNCTION ibis_udfs.public.object_values("obj" OBJECT) RETURNS ARRAY LANGUAGE JAVASCRIPT STRICT AS ' return Object.values(obj) '
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE TABLE TEST (SOME_REF DECIMAL(38, 0) NOT NULL FOREIGN KEY REFERENCES SOME_OTHER_TABLE (ID))
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE FUNCTION my_udf(location OBJECT(city VARCHAR, zipcode DECIMAL(38, 0), val ARRAY(BOOLEAN))) RETURNS VARCHAR AS $$ SELECT 'foo' $$
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE FUNCTION my_udtf(foo BOOLEAN) RETURNS TABLE(col1 ARRAY(INT)) AS $$ WITH t AS (SELECT CAST([1, 2, 3] AS ARRAY(INT)) AS c) SELECT c FROM t $$
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE SEQUENCE seq1 WITH START=1, INCREMENT=1 ORDER
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE SEQUENCE seq1 WITH START=1 INCREMENT=1 ORDER
----
-- source: sqlglot tests/dialects/test_snowflake.py
create external table et2(
  col1 date as (parse_json(metadata$external_table_partition):COL1::date),
  col2 varchar as (parse_json(metadata$external_table_partition):COL2::varchar),
  col3 number as (parse_json(metadata$external_table_partition):COL3::number))
  partition by (col1,col2,col3)
  location=@s2/logs/
  partition_type = user_specified
  file_format = (type = parquet compression = gzip binary_as_text = false)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE TRANSIENT TABLE a (id INT)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE a TAG (key1='value_1', key2='value_2')
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE a WITH TAG (key1='value_1')
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE FUNCTION a(x DATE, y BIGINT) RETURNS ARRAY LANGUAGE JAVASCRIPT AS $$ SELECT 1 $$
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE FUNCTION a() RETURNS TABLE (b INT) AS 'SELECT 1'
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE FUNCTION a() RETURNS INT IMMUTABLE AS 'SELECT 1'
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE FUNCTION repro_fn() RETURNS INT LANGUAGE PYTHON HANDLER = 'fn' RUNTIME_VERSION='3.11' PACKAGES=() AS '\ndef fn():\n    return 1\n'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT rollback FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
WITH rollback(rollback) AS (SELECT 1) SELECT rollback.rollback FROM rollback
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ROLLBACK(3)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 1 rollback
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT rollback.x FROM (SELECT 1 AS x) rollback
----
-- source: sqlglot tests/dialects/test_snowflake.py
CALL a.b.c(x, y)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE PROCEDURE a.b.c(x INT, y VARIANT) RETURNS OBJECT EXECUTE AS CALLER AS 'BEGIN SELECT 1; END;'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE('MYTABLE')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE($MYVAR)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE(?)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE(:BINDING)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE($MYVAR) WHERE COL1 = 10
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE('t1') AS f
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM (TABLE('t1') CROSS JOIN TABLE('t2'))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE('t1'), LATERAL (SELECT * FROM t2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE('t1') UNION ALL SELECT * FROM TABLE('t2')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE('t1') TABLESAMPLE BERNOULLI (20.3)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE('MYDB."MYSCHEMA"."MYTABLE"')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE($$MYDB. "MYSCHEMA"."MYTABLE"$$)
----
-- source: sqlglot tests/dialects/test_snowflake.py
select
              dag_report.acct_id,
              dag_report.report_date,
              dag_report.report_uuid,
              dag_report.airflow_name,
              dag_report.dag_id,
              f.value::varchar as operator
            from cs.telescope.dag_report,
            table(flatten(input=>split(operators, ','))) f
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT
              uc.user_id,
              uc.start_ts AS ts,
              CASE
                WHEN uc.start_ts::DATE >= '2023-01-01' AND uc.country_code IN ('US') AND uc.user_id NOT IN (
                  SELECT DISTINCT
                    _id
                  FROM
                    users,
                    LATERAL FLATTEN(INPUT => PARSE_JSON(flags)) datasource
                  WHERE datasource.value:name = 'something'
                )
                  THEN 'Sample1'
                  ELSE 'Sample2'
              END AS entity
            FROM user_countries AS uc
            LEFT JOIN (
              SELECT user_id, MAX(IFF(service_entity IS NULL,1,0)) AS le_null
              FROM accepted_user_agreements
              GROUP BY 1
            ) AS aua
              ON uc.user_id = aua.user_id
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT value FROM TABLE(FLATTEN(input => SELECT PARSE_JSON('[1, 2]')))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE(FLATTEN(input => parse_json('[1, ,77]'))) f
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE(FLATTEN(input => parse_json('{"a":1, "b":[77,88]}'), outer => true)) f
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE(FLATTEN(input => parse_json('{"a":1, "b":[77,88]}'), path => 'b')) f
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE(FLATTEN(input => parse_json('[]'))) f
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE(FLATTEN(input => parse_json('[]'), outer => true)) f
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE(FLATTEN(input => parse_json('{"a":1, "b":[77,88], "c": {"d":"X"}}'))) f
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE(FLATTEN(input => parse_json('{"a":1, "b":[77,88], "c": {"d":"X"}}'), recursive => true)) f
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE(FLATTEN(input => parse_json('{"a":1, "b":[77,88], "c": {"d":"X"}}'), recursive => true, mode => 'object')) f
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT id as "ID",
              f.value AS "Contact",
              f1.value:type AS "Type",
              f1.value:content AS "Details"
            FROM persons p,
              lateral flatten(input => p.c, path => 'contact') f,
              lateral flatten(input => f.value:business) f1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT id as "ID",
              value AS "Contact"
            FROM persons p,
              lateral flatten(input => p.c, path => 'contact')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 1 MINUS SELECT 1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT t1.c1, t2.c2 FROM t1, t2 WHERE t1.c1 = t2.c2 (+)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT t1.c1, t2.c2 FROM t1, t2 WHERE t1.c1 (+) = t2.c2
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT t1.c1, t2.c2 FROM t1, t2 WHERE t1.c1 = t2.c2(+)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT $1 AS "_1" FROM VALUES ('a'), ('b')
----
-- source: sqlglot tests/dialects/test_snowflake.py
DESCRIBE SEMANTIC VIEW TPCDS_SEMANTIC_VIEW_SM
----
-- source: sqlglot tests/dialects/test_snowflake.py
DESC SEMANTIC VIEW TPCDS_SEMANTIC_VIEW_SM
----
-- source: sqlglot tests/dialects/test_snowflake.py
DESCRIBE TABLE db.table
----
-- source: sqlglot tests/dialects/test_snowflake.py
DESCRIBE db.table
----
-- source: sqlglot tests/dialects/test_snowflake.py
DESC TABLE db.table
----
-- source: sqlglot tests/dialects/test_snowflake.py
DESC VIEW db.table
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEARCH((play, line), 'dream')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEARCH(line, 'king', ANALYZER => 'UNICODE_ANALYZER')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEARCH(character, 'king queen', SEARCH_MODE => 'AND')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEARCH(line, 'king', ANALYZER => 'UNICODE_ANALYZER', SEARCH_MODE => 'OR')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEARCH(line, 'king')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEARCH(line, 'king', SEARCH_MODE => 'AND', ANALYZER => 'PATTERN_ANALYZER')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGEXP_COUNT('hello world', 'l ')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGEXP_COUNT('hello world', 'l', 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGEXP_COUNT('hello world', 'l', 1, 'i')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGEXP_COUNT('hello', 'l')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGEXP_COUNT('hello world', 'l', 7)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGEXP_COUNT('Hello World', 'L', 1, 'im')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGEXP_COUNT(subject, pattern)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGEXP_INSTR('abc', 'a')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGEXP_INSTR('abc', 'a', 1, 1, 0, 'i')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGEXP_INSTR(subject, pattern)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGEXP_INSTR(subject, pattern, 5)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGEXP_INSTR(subject, pattern, 1, 2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT REGEXP_INSTR(subject, pattern, 1, 1, 0, 'im')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW USERS
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW TERSE USERS
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW USERS LIKE '_foo%' STARTS WITH 'bar' LIMIT 5 FROM 'baz'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW TERSE DATABASES
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW TERSE DATABASES HISTORY LIKE 'foo' STARTS WITH 'bla' LIMIT 5 FROM 'bob' WITH PRIVILEGES USAGE, MODIFY
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW FILE FORMATS
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW FILE FORMATS LIKE 'foo' IN DATABASE db1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW FILE FORMATS LIKE 'foo' IN SCHEMA db1.schema1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW FUNCTIONS
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW FUNCTIONS LIKE 'foo' IN CLASS bla
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW PROCEDURES
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW PROCEDURES LIKE 'foo' IN APPLICATION app
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW PROCEDURES LIKE 'foo' IN APPLICATION PACKAGE pkg
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW STAGES
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW STAGES LIKE 'foo' IN DATABASE db1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW STAGES LIKE 'foo' IN SCHEMA db1.schema1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW WAREHOUSES
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW WAREHOUSES LIKE 'foo' WITH PRIVILEGES USAGE, MODIFY
----
-- source: sqlglot tests/dialects/test_snowflake.py
show terse schemas in database db1 starts with 'a' limit 10 from 'b'
----
-- source: sqlglot tests/dialects/test_snowflake.py
show terse objects in schema db1.schema1 starts with 'a' limit 10 from 'b'
----
-- source: sqlglot tests/dialects/test_snowflake.py
show terse objects in db1.schema1 starts with 'a' limit 10 from 'b'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW COLUMNS
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW COLUMNS IN TABLE dt_test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW COLUMNS LIKE '_foo%' IN TABLE dt_test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW COLUMNS IN VIEW
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW COLUMNS LIKE '_foo%' IN VIEW dt_test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW TABLES LIKE 'line%' IN tpch.public
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW TABLES HISTORY IN tpch.public
----
-- source: sqlglot tests/dialects/test_snowflake.py
show terse tables in schema db1.schema1 starts with 'a' limit 10 from 'b'
----
-- source: sqlglot tests/dialects/test_snowflake.py
show terse tables in db1.schema1 starts with 'a' limit 10 from 'b'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW ICEBERG TABLES IN db1.schema1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW TERSE ICEBERG TABLES IN db1.schema1
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER ICEBERG TABLE t RENAME TO x
----
-- source: sqlglot tests/dialects/test_snowflake.py
DROP ICEBERG TABLE t
----
-- source: sqlglot tests/dialects/test_snowflake.py
DROP ICEBERG TABLE IF EXISTS t
----
-- source: sqlglot tests/dialects/test_snowflake.py
DROP ICEBERG TABLE t RESTRICT
----
-- source: sqlglot tests/dialects/test_snowflake.py
DROP ICEBERG TABLE IF EXISTS t RESTRICT
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW PRIMARY KEYS
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW PRIMARY KEYS IN ACCOUNT
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW PRIMARY KEYS IN DATABASE
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW PRIMARY KEYS IN DATABASE foo
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW PRIMARY KEYS IN TABLE
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW PRIMARY KEYS IN TABLE foo
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW PRIMARY KEYS IN "TEST"."PUBLIC"."foo"
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW TERSE PRIMARY KEYS IN "TEST"."PUBLIC"."foo"
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW TERSE VIEWS
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW VIEWS
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW VIEWS LIKE 'foo%'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW VIEWS IN ACCOUNT
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW VIEWS IN DATABASE
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW VIEWS IN DATABASE foo
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW VIEWS IN SCHEMA foo
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW VIEWS IN foo
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW UNIQUE KEYS
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW UNIQUE KEYS IN ACCOUNT
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW UNIQUE KEYS IN DATABASE
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW UNIQUE KEYS IN DATABASE foo
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW UNIQUE KEYS IN TABLE
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW UNIQUE KEYS IN TABLE foo
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW UNIQUE KEYS IN "TEST"."PUBLIC"."foo"
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW TERSE UNIQUE KEYS IN "TEST"."PUBLIC"."foo"
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW IMPORTED KEYS
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW IMPORTED KEYS IN ACCOUNT
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW IMPORTED KEYS IN DATABASE
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW IMPORTED KEYS IN DATABASE foo
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW IMPORTED KEYS IN TABLE
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW IMPORTED KEYS IN TABLE foo
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW IMPORTED KEYS IN "TEST"."PUBLIC"."foo"
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW TERSE IMPORTED KEYS IN "TEST"."PUBLIC"."foo"
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW TERSE SEQUENCES
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW SEQUENCES
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW SEQUENCES LIKE '_foo%' IN ACCOUNT
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW SEQUENCES LIKE '_foo%' IN DATABASE
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW SEQUENCES LIKE '_foo%' IN DATABASE foo
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW SEQUENCES LIKE '_foo%' IN SCHEMA
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW SEQUENCES LIKE '_foo%' IN SCHEMA foo
----
-- source: sqlglot tests/dialects/test_snowflake.py
SHOW SEQUENCES LIKE '_foo%' IN foo
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TRY_CAST(x AS DOUBLE)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TRY_CAST(FOO() AS TEXT)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TRY_PARSE_JSON(x)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CAST(1.5 AS DECFLOAT)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE t (x DECFLOAT)
----
-- source: sqlglot tests/dialects/test_snowflake.py
COPY INTO test (c1) FROM (SELECT $1.c1 FROM @mystage)
----
-- source: sqlglot tests/dialects/test_snowflake.py
COPY INTO temp FROM @random_stage/path/ FILE_FORMAT = (TYPE=CSV FIELD_DELIMITER='|' NULL_IF=('str1', 'str2') FIELD_OPTIONALLY_ENCLOSED_BY='"' TIMESTAMP_FORMAT='TZHTZM YYYY-MM-DD HH24:MI:SS.FF9' DATE_FORMAT='TZHTZM YYYY-MM-DD HH24:MI:SS.FF9' BINARY_FORMAT=BASE64) VALIDATION_MODE = 'RETURN_3_ROWS'
----
-- source: sqlglot tests/dialects/test_snowflake.py
COPY INTO load1 FROM @%load1/data1/ CREDENTIALS = (AWS_KEY_ID='id' AWS_SECRET_KEY='key' AWS_TOKEN='token') FILES = ('test1.csv', 'test2.csv') FORCE = TRUE
----
-- source: sqlglot tests/dialects/test_snowflake.py
COPY INTO mytable (col1, col2) FROM 's3://mybucket/data/files' STORAGE_INTEGRATION = "storage" ENCRYPTION = (TYPE='NONE' MASTER_KEY='key') FILES = ('file1', 'file2') PATTERN = 'pattern' FILE_FORMAT = (FORMAT_NAME=my_csv_format NULL_IF=('')) PARSE_HEADER = TRUE
----
-- source: sqlglot tests/dialects/test_snowflake.py
COPY INTO @my_stage/result/data FROM (SELECT * FROM orderstiny) FILE_FORMAT = (TYPE='csv')
----
-- source: sqlglot tests/dialects/test_snowflake.py
COPY INTO mytable FILE_FORMAT = (TYPE='csv')
----
-- source: sqlglot tests/dialects/test_snowflake.py
COPY INTO MY_DATABASE.MY_SCHEMA.MY_TABLE FROM @MY_DATABASE.MY_SCHEMA.MY_STAGE/my_path FILE_FORMAT = (FORMAT_NAME=MY_DATABASE.MY_SCHEMA.MY_FILE_FORMAT)
----
-- source: sqlglot tests/dialects/test_snowflake.py
COPY INTO 's3://example/data.csv'
    FROM EXTRA.EXAMPLE.TABLE
    CREDENTIALS = ()
    FILE_FORMAT = (TYPE = CSV COMPRESSION = NONE NULL_IF = ('') FIELD_OPTIONALLY_ENCLOSED_BY = '"')
    HEADER = TRUE
    OVERWRITE = TRUE
    SINGLE = TRUE
----
-- source: sqlglot tests/dialects/test_snowflake.py
COPY INTO 's3://example/data.csv'
    FROM EXTRA.EXAMPLE.TABLE
    STORAGE_INTEGRATION = S3_INTEGRATION
    FILE_FORMAT = (TYPE=CSV COMPRESSION=NONE NULL_IF=('') FIELD_OPTIONALLY_ENCLOSED_BY='"')
    HEADER = TRUE
    OVERWRITE = TRUE
    SINGLE = TRUE
----
-- source: sqlglot tests/dialects/test_snowflake.py
PUT 'file:///dir/tmp.csv' @"my_DB"."schEMA1"."MYstage"
----
-- source: sqlglot tests/dialects/test_snowflake.py
PUT 'file:///dir/tmp.csv' @s1/test
----
-- source: sqlglot tests/dialects/test_snowflake.py
GET @"my_DB"."schEMA1"."MYstage" 'file:///dir/tmp.csv'
----
-- source: sqlglot tests/dialects/test_snowflake.py
GET @%table file:///dir/tmp.csv
----
-- source: sqlglot tests/dialects/test_snowflake.py
GET @s1/test file:///dir/tmp.csv PARALLEL=1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT $1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT $1.elem
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT $1:a.b
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT t.$23:a.b
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT t.$17:a[0].b[0].c
----
-- source: sqlglot tests/dialects/test_snowflake.py
WITH t AS (SELECT PARSE_JSON('{"a": [1, 2]}') AS v), s AS (SELECT 1 AS x) SELECT t.v:a[s.x] FROM t, s
----
-- source: sqlglot tests/dialects/test_snowflake.py
WITH t AS (SELECT PARSE_JSON('{"c": [{"r": 1}]}') AS v), s AS (SELECT 0 AS x) SELECT t.v:c[s.x]:r FROM t, s
----
-- source: sqlglot tests/dialects/test_snowflake.py
WITH t AS (SELECT PARSE_JSON('{"c": [{"r": {"d": 1}}]}') AS v), s AS (SELECT 0 AS x) SELECT t.v:c[s.x]:r:d::varchar FROM t, s
----
-- source: sqlglot tests/dialects/test_snowflake.py
WITH t AS (SELECT PARSE_JSON('{"a": {"b": [1, 2]}}') AS v), s AS (SELECT 1 AS x) SELECT t.v:a:b[s.x] FROM t, s
----
-- source: sqlglot tests/dialects/test_snowflake.py
WITH t AS (SELECT PARSE_JSON('{"c": [{"r": 1}]}') AS v), s AS (SELECT 0 AS x) SELECT t.v:c[s.x].r FROM t, s
----
-- source: sqlglot tests/dialects/test_snowflake.py
WITH t AS (SELECT PARSE_JSON('{"c": [{"r": {"d": 1}}]}') AS v), s AS (SELECT 0 AS x) SELECT t.v:c[s.x].r.d FROM t, s
----
-- source: sqlglot tests/dialects/test_snowflake.py
WITH t AS (SELECT PARSE_JSON('{"c": [{"r": {"d": {"e": 1}}}]}') AS v), s AS (SELECT 0 AS x) SELECT t.v:c[s.x].r.d.e FROM t, s
----
-- source: sqlglot tests/dialects/test_snowflake.py
WITH t AS (SELECT PARSE_JSON('{"a": {"b": [{"r": {"d": 1}}]}}') AS v), s AS (SELECT 0 AS x) SELECT t.v:a.b[s.x].r.d FROM t, s
----
-- source: sqlglot tests/dialects/test_snowflake.py
WITH t AS (SELECT PARSE_JSON('{"a": {"b": [{"r": {"d": [10, 20, 30]}}]}}') AS v), s AS (SELECT 0 AS x, 2 AS y) SELECT t.v:a.b[s.x].r.d[s.y] FROM t, s
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT col:"customer's department"
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE tbl SET DATA_RETENTION_TIME_IN_DAYS=1
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE tbl SET DEFAULT_DDL_COLLATION='test'
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE foo SET COMMENT='bar'
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE foo SET CHANGE_TRACKING=FALSE
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE table1 SET TAG foo.bar = 'baz'
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE IF EXISTS foo SET TAG a = 'a', b = 'b', c = 'c'
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE tbl SET STAGE_FILE_FORMAT = (TYPE=CSV FIELD_DELIMITER='|' NULL_IF=('') FIELD_OPTIONALLY_ENCLOSED_BY='"' TIMESTAMP_FORMAT='TZHTZM YYYY-MM-DD HH24:MI:SS.FF9' DATE_FORMAT='TZHTZM YYYY-MM-DD HH24:MI:SS.FF9' BINARY_FORMAT=BASE64)
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE tbl SET STAGE_COPY_OPTIONS = (ON_ERROR=SKIP_FILE SIZE_LIMIT=5 PURGE=TRUE MATCH_BY_COLUMN_NAME=CASE_SENSITIVE)
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE foo UNSET TAG a, b, c
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE foo UNSET DATA_RETENTION_TIME_IN_DAYS, CHANGE_TRACKING
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER SESSION SET autocommit = FALSE, QUERY_TAG = 'qtag', JSON_INDENT = 1
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER SESSION UNSET autocommit, QUERY_TAG
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT C1 FROM t1 CHANGES (INFORMATION => APPEND_ONLY) AT (STREAM => 's1') END (TIMESTAMP => $ts2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT C1 FROM t1 CHANGES (INFORMATION => APPEND_ONLY) BEFORE (STATEMENT => 'STMT_ID') END (TIMESTAMP => $ts2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 1 FROM some_table CHANGES (INFORMATION => APPEND_ONLY) AT (TIMESTAMP => TO_TIMESTAMP_TZ('2024-07-01 00:00:00+00:00')) END (TIMESTAMP => TO_TIMESTAMP_TZ('2024-07-01 14:28:59.999999+00:00'))
----
-- source: sqlglot tests/dialects/test_snowflake.py
GRANT ALL PRIVILEGES ON FUNCTION mydb.myschema.ADD5(number) TO ROLE analyst
----
-- source: sqlglot tests/dialects/test_snowflake.py
REVOKE ALL PRIVILEGES ON FUNCTION mydb.myschema.ADD5(number) FROM ROLE analyst
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT :1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT :1, :2
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT :1 + :2
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MAX_BY(a, b) FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT MIN_BY(a, b) FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE VIEW FOO (A, B) COPY GRANTS AS SELECT A, B FROM TBL
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE MATERIALIZED VIEW FOO COPY GRANTS (A, B) AS SELECT A, B FROM TBL
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE MATERIALIZED VIEW FOO COPY GRANTS (A, B) COMMENT='foo' TAG (a='b') AS SELECT A, B FROM TBL
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE VIEW FOO (A, B) AS SELECT A, B FROM TBL
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE MATERIALIZED VIEW FOO (A, B) AS SELECT A, B FROM TBL
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE VIEW v (c) CHANGE_TRACKING=TRUE AS SELECT 1 AS c
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE VIEW my_view CHANGE_TRACKING=TRUE (id) AS SELECT * FROM my_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE VIEW v WITH ROW ACCESS POLICY mypolicy ON (col1) AS SELECT col1 FROM t1
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE VIEW v WITH ROW ACCESS POLICY db.schema.mypolicy ON (col1, col2) AS SELECT col1, col2 FROM t1
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE VIEW v (COL1 COMMENT 'description') WITH ROW ACCESS POLICY db.schema.policy ON (COL1) COMMENT='some comment' AS (SELECT a FROM t1 LEFT JOIN t2 ON t1.id = t2.id)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE VIEW v ROW ACCESS POLICY p ON (c) AS SELECT c FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TABLE t (c INT) ROW ACCESS POLICY p ON (c)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE VIEW v WITH ROW ACCESS POLICY #unknown_policy AS SELECT 1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM SEMANTIC_VIEW(foo METRICS a.b, a.c DIMENSIONS a.b, a.c WHERE a.b > '1995-01-01')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT col1, col2, metric1 FROM SEMANTIC_VIEW(mydb.myschema.my_semantic_view METRICS metric1 DIMENSIONS col1, DATE_TRUNC('MONTH', timestamp_col) AS col2) ORDER BY col1, col2 DESC
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT GET([4, 5, 6], 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT GET(col::MAP(INTEGER, VARCHAR), 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT GET(v, 'field')
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE SEQUENCE seq  START=5 comment = 'foo' INCREMENT=10
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE SEQUENCE seq WITH START=1 INCREMENT=1
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT model!mladmin
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT model!PREDICT(1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT m!PREDICT(INPUT_DATA => {*}) AS p FROM tbl
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT m!PREDICT(INPUT_DATA => {tbl.*}) AS p FROM tbl
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM TABLE(model_trained_with_labeled_data!DETECT_ANOMALIES(INPUT_DATA => TABLE(view_with_data_to_analyze), TIMESTAMP_COLNAME => 'date', TARGET_COLNAME => 'sales', CONFIG_OBJECT => OBJECT_CONSTRUCT('prediction_interval', 0.99)))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ROUND(2.25) AS value
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ROUND(2.25, 1) AS value
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ROUND(EXPR => 2.25, SCALE => 1) AS value
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ROUND(SCALE => 1, EXPR => 2.25) AS value
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ROUND(2.25, 1, 'HALF_AWAY_FROM_ZERO') AS value
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ROUND(EXPR => 2.25, SCALE => 1, ROUNDING_MODE => 'HALF_AWAY_FROM_ZERO') AS value
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ROUND(2.25, 1, 'HALF_TO_EVEN') AS value
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ROUND(ROUNDING_MODE => 'HALF_TO_EVEN', EXPR => 2.25, SCALE => 1) AS value
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ROUND(SCALE => 1, EXPR => 2.25, , ROUNDING_MODE => 'HALF_TO_EVEN') AS value
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ROUND(EXPR => 2.25, SCALE => 1, ROUNDING_MODE => 'HALF_TO_EVEN') AS value
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ROUND(2.256, 1.8) AS value
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ROUND(2.256, CAST(1.8 AS DECIMAL(38, 0))) AS value
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT GETBIT(11, 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT FLOOR(1.753, 2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT FLOOR(123.45, -1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT FLOOR(a + b, 2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT FLOOR(1.234, 1.5)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEQ1() FROM test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEQ1(0) FROM test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEQ1(1) FROM test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEQ2() FROM test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEQ2(0) FROM test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEQ2(1) FROM test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEQ4() FROM test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEQ4(0) FROM test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEQ4(1) FROM test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEQ8() FROM test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEQ8(0) FROM test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEQ8(1) FROM test
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 1 FROM TABLE(GENERATOR(ROWCOUNT => 10))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 1 FROM TABLE(GENERATOR(TIMELIMIT => 5))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 1 FROM TABLE(GENERATOR(ROWCOUNT => 10, TIMELIMIT => 5))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 1 FROM TABLE(GENERATOR(10))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 1 FROM TABLE(GENERATOR(10, 5))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT 1 FROM TABLE(GENERATOR(ROWCOUNT => 5))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEQ8() FROM TABLE(GENERATOR(ROWCOUNT => 5))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM (TABLE(GENERATOR(ROWCOUNT => 5)) JOIN other ON 1 = 1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CEIL(1.753, 2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CEIL(123.45, -1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CEIL(a + b, 2)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CEIL(1.234, 1.5)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CORR(a, b)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CORR(a, b) OVER (PARTITION BY c)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CORR(a, b) FILTER(WHERE c > 0)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CORR(a, b) FILTER(WHERE c > 0) OVER (PARTITION BY d)
----
-- source: sqlglot tests/dialects/test_snowflake.py
UPDATE test SET t = 1 FROM t1
----
-- source: sqlglot tests/dialects/test_snowflake.py
UPDATE test SET t = 1 FROM t2 JOIN t3 ON t2.id = t3.id
----
-- source: sqlglot tests/dialects/test_snowflake.py
UPDATE test SET t = 1 FROM (SELECT id FROM test2) AS t2 JOIN test3 AS t3 ON t2.id = t3.id
----
-- source: sqlglot tests/dialects/test_snowflake.py
UPDATE sometesttable u FROM (SELECT 5195 AS new_count, '01bee1e5-0000-d31e-0000-e80ef02b9f27' query_id ) b SET qry_hash_count = new_count WHERE u.sample_query_id  = b.query_id
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_FLATTEN([['a', 'b'], ['c', 'd', 'e']])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_FLATTEN([[[1, 2], [3]], [[4], [5]]])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_FLATTEN([[1, NULL, 3], [4]])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_FLATTEN([[]])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_EXCEPT([1, 2, 3], [2])
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT ARRAY_POSITION(2, ARRAY_CONSTRUCT(1, 2, 3))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SPACE(5)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SPACE(3.7)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SPACE(NULL)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CHARINDEX('sub', 'testsubstring', -1)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT CHARINDEX('sub', 'testsubstring', p)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM a CROSS DIRECTED JOIN b USING (id)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM a INNER DIRECTED JOIN b USING (id)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT * FROM a NATURAL INNER DIRECTED JOIN b USING (id)
----
-- source: sqlglot tests/dialects/test_snowflake.py
UNDROP TABLE my_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
UNDROP SCHEMA my_schema
----
-- source: sqlglot tests/dialects/test_snowflake.py
UNDROP DATABASE my_db
----
-- source: sqlglot tests/dialects/test_snowflake.py
UNDROP ACCOUNT my_account
----
-- source: sqlglot tests/dialects/test_snowflake.py
UNDROP NOTEBOOK my_nb
----
-- source: sqlglot tests/dialects/test_snowflake.py
UNDROP SNAPSHOT my_snap
----
-- source: sqlglot tests/dialects/test_snowflake.py
UNDROP STREAMLIT my_app
----
-- source: sqlglot tests/dialects/test_snowflake.py
UNDROP TAG my_tag
----
-- source: sqlglot tests/dialects/test_snowflake.py
UNDROP TYPE my_type
----
-- source: sqlglot tests/dialects/test_snowflake.py
UNDROP DYNAMIC TABLE my_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
UNDROP EXTERNAL VOLUME my_vol
----
-- source: sqlglot tests/dialects/test_snowflake.py
UNDROP ICEBERG TABLE my_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
UNDROP TABLE db.schema.my_table
----
-- source: sqlglot tests/dialects/test_snowflake.py
UNDROP SNAPSHOT IDENTIFIER('my_snap')
----
-- source: sqlglot tests/dialects/test_snowflake.py
UNDROP SNAPSHOT my_snap RENAME TO new_snap
----
-- source: sqlglot tests/dialects/test_snowflake.py
ALTER TABLE foo DROP COLUMN col1, col2
----
-- source: sqlglot tests/dialects/test_snowflake.py
LS @~
----
-- source: sqlglot tests/dialects/test_snowflake.py
ls @named_stage
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT list, ls FROM list
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT x AS list, y AS ls FROM t
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE FUNCTION ibis_udfs.public.object_values("obj" OBJECT) RETURNS ARRAY LANGUAGE JAVASCRIPT RETURNS NULL ON NULL INPUT AS ' return Object.values(obj) '
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE FUNCTION a(x DOUBLE) RETURNS DOUBLE LANGUAGE SQL CALLED ON NULL INPUT AS ' x * 2 '
----
-- source: sqlglot tests/dialects/test_snowflake.py
PUT file:///dir/tmp.csv @s1/test PARALLEL=1 AUTO_COMPRESS=FALSE source_compression=gzip OVERWRITE=TRUE
----
-- source: sqlglot tests/dialects/test_snowflake.py
GET @s1/test 'file:///dir/tmp.csv'
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TRY_PARSE_JSON('{"x: 1}')
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE WAREHOUSE x
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE STREAMLIT x
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TEMPORARY STAGE stage1 FILE_FORMAT=(TYPE=PARQUET)
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE OR REPLACE TAG IF NOT EXISTS cost_center COMMENT='cost_center tag'
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE TEMPORARY FILE FORMAT fileformat1 TYPE=PARQUET COMPRESSION=auto
----
-- source: sqlglot tests/dialects/test_snowflake.py
CREATE STORAGE INTEGRATION s3_int
TYPE=EXTERNAL_STAGE
STORAGE_PROVIDER='S3'
STORAGE_AWS_ROLE_ARN='arn:aws:iam::001234567890:role/myrole'
ENABLED=TRUE
STORAGE_ALLOWED_LOCATIONS=('s3://mybucket1/path1/', 's3://mybucket2/path2/')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT number
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT TO_TIMESTAMP(123.4)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_PART(year FROM CAST('2024-04-08' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_PART('month' FROM CAST('2024-04-08' AS DATE))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATE_PART(day FROM a)
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT SEARCH_IP(col, '192.168.0.0')
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT value FROM TABLE(SPLIT_TO_TABLE('a.b.c', '.'))
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT DATEADD(DAY, -7, DATEADD(t.m, 1, CAST('2023-01-03' AS DATE))) FROM (SELECT 'month' AS m) AS t
----
-- source: sqlglot tests/dialects/test_snowflake.py
SELECT FILE_URL FROM DIRECTORY(@mystage) WHERE SIZE > 100000
----
