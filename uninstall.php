<?php
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit; // Exit if accessed directly
}

global $wpdb;
$table_name = $wpdb->prefix . 'activity_log';
$wpdb->query("DROP TABLE IF EXISTS $table_name");