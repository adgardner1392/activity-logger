<?php
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit; // Exit if accessed directly
}

global $wpdb;
$table_name = $wpdb->prefix . 'activity_log';

// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.SlowDBQuery, WordPress.VIP.DirectDBSchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Direct query required for uninstallation, schema changes allowed, and table name is constant and safe.
$wpdb->query( "DROP TABLE IF EXISTS {$table_name}" );
