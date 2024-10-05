<?php
/*
Plugin Name: Activity Logger
Plugin URI: https://github.com/adgardner1392/activity-logger
Description: Logs all activity within the CMS by logged-in users (e.g., editing posts, deleting posts, changing settings).
Version: 1.0
Author: Adam Gardner
Author URI: https://github.com/adgardner1392
License: GPLv2 or later
Text Domain: activity-logger
Domain Path: /languages
*/

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

class Activity_Logger {

    // Declare a global variable to store the username
    private $logged_in_user_login = null;

    public function __construct() {
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'activity_log';
        $this->create_log_table();

        add_action('wp_insert_post', [$this, 'log_post_activity'], 10, 3);
        add_action('delete_post', [$this, 'log_delete_post'], 10, 1);
        add_action('add_attachment', [$this, 'log_upload_attachment'], 10, 1);
        add_action('updated_option', [$this, 'log_option_update'], 10, 3);
        add_action('activated_plugin', [$this, 'log_plugin_activity'], 10, 2);
        add_action('deactivated_plugin', [$this, 'log_plugin_activity'], 10, 2);
        add_action('wp_trash_post', [$this, 'log_trash_post'], 10, 1);
        add_action('admin_menu', [$this, 'add_admin_menu']);

        // User profile and authentication logging
        add_action('profile_update', [$this, 'log_profile_update'], 10, 2);
        add_action('wp_login', [$this, 'log_user_login'], 10, 2);
        // Capture user info before logout
        add_action('set_current_user', [$this, 'capture_user_login']);
        // Hook into logout event
        add_action('wp_logout', [$this, 'log_user_logout']);
        add_action('after_password_reset', [$this, 'log_password_reset'], 10, 2);
        
        // Enqueue scripts and styles
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_assets']);
        
        // Handle export logs action
        add_action('admin_post_activity_logger_export_logs', [$this, 'export_logs_csv']);
        // Handle delete log action
        add_action('admin_post_activity_logger_delete_log', [$this, 'delete_log_entry']);        
    }

    // Enqueue JavaScript and CSS files
    public function enqueue_admin_assets() {
        // Only enqueue on the plugin's admin page
        $screen = get_current_screen();
        if ($screen->id !== 'toplevel_page_activity-logger') {
            return;
        }

        // Enqueue JavaScript file
        wp_enqueue_script(
            'activity-logger-admin-js',
            plugin_dir_url(__FILE__) . 'js/admin.js',
            ['jquery'], // Add dependencies if necessary
            '1.0',
            true // Enqueue in the footer
        );

        // Enqueue optional CSS file
        wp_enqueue_style(
            'activity-logger-admin-css',
            plugin_dir_url(__FILE__) . 'css/admin.css',
            [],
            '1.0'
        );
    }

    private function create_log_table() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$this->table_name} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            username VARCHAR(60) NOT NULL,
            action TEXT NOT NULL,
            log_time DATETIME NOT NULL,
            PRIMARY KEY (id)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);

        // Ensure the 'username' column has the correct data type
        $column = $wpdb->get_row("SHOW COLUMNS FROM {$this->table_name} LIKE 'username'");
        if ($column && strpos($column->Type, 'varchar') === false) {
            $wpdb->query("ALTER TABLE {$this->table_name} MODIFY username VARCHAR(60) NOT NULL;");
        }
    }

    public function log_post_activity($post_ID, $post, $update) {
        if (!$this->is_cron_allowed() && defined('DOING_CRON') && DOING_CRON) {
            return;
        }
    
        // Ignore autosaves, revisions, customizer changes, and posts being trashed
        if (wp_is_post_autosave($post_ID) || wp_is_post_revision($post_ID) || is_customize_preview() || $post->post_status === 'trash') {
            return;
        }
    
        $user = wp_get_current_user();
        $post_type_obj = get_post_type_object($post->post_type);
        $post_type_name = !empty($post_type_obj) ? $post_type_obj->labels->singular_name : 'Post';
    
        $action = $update ? 'updated' : 'created';
        $post_title = !empty($post->post_title) ? $post->post_title : '(no title)';
        
        $message = sprintf(
            '%s %s: %s (ID: %d) by user %s',
            $post_type_name,
            $action,
            $post_title,
            $post_ID,
            $user->user_login
        );
        
        $this->log_activity($message);
    }
    

    public function log_profile_update($user_id, $old_user_data) {
        $user = get_userdata($user_id);
    
        // Check which fields were updated
        $changes = [];
        if ($old_user_data->user_email !== $user->user_email) {
            $changes[] = 'email';
        }
        if ($old_user_data->first_name !== $user->first_name) {
            $changes[] = 'first name';
        }
        if ($old_user_data->last_name !== $user->last_name) {
            $changes[] = 'last name';
        }
    
        // Only log if there were changes
        if (!empty($changes)) {
            $message = sprintf(
                'Profile updated: %s (ID: %d) changed %s by user %s',
                $user->user_login,
                $user->ID,
                implode(', ', $changes),
                wp_get_current_user()->user_login
            );
            $this->log_activity($message);
        }
    }


    public function log_user_login($user_login, $user) {
        $message = sprintf(
            'User logged in: %s (ID: %d)',
            $user_login,  // Correct username passed by wp_login hook
            $user->ID     // Correct user ID passed by wp_login hook
        );
        $this->log_activity($message, $user_login);  // Pass the correct username to log_activity()
    }

    // Capture the current user's login before the logout happens
    public function capture_user_login() {
        $user = wp_get_current_user();
        if ($user && $user->ID) {
            $this->logged_in_user_login = $user->user_login;
        }
    }
    
    // Log user logout using the captured login
    public function log_user_logout() {
        if ($this->logged_in_user_login) {
            $message = sprintf(
                'User logged out: %s',
                $this->logged_in_user_login
            );
            $this->log_activity($message, $this->logged_in_user_login);
        }
    }
    

    public function log_password_reset($user, $new_password) {
        $message = sprintf(
            'Password reset: %s (ID: %d)',
            $user->user_login,
            $user->ID
        );
        $this->log_activity($message);
    }    

    public function log_upload_attachment($post_ID) {
        $user = wp_get_current_user();

        // Retrieve the full file path and get the filename with extension
        $file_path = get_attached_file($post_ID);
        $filename = $file_path ? basename($file_path) : get_the_title($post_ID); // Fallback to post title if no file path

        $message = sprintf(
            'Media uploaded: %s (ID: %d) by user %s',
            $filename,
            $post_ID,
            $user->user_login
        );

        $this->log_activity($message);
    }

    public function log_delete_post($post_ID) {
        if (!$this->is_cron_allowed() && defined('DOING_CRON') && DOING_CRON) {
            return;
        }
    
        // Ignore customizer and autosave-related deletions
        if (wp_is_post_autosave($post_ID) || wp_is_post_revision($post_ID) || is_customize_preview()) {
            return;
        }
    
        $user = wp_get_current_user();
        $post = get_post($post_ID);
        $post_type_obj = get_post_type_object($post->post_type);
        $post_type_name = !empty($post_type_obj) ? $post_type_obj->labels->singular_name : 'Post';
    
        if ($post->post_type === 'attachment') {
            $file_path = get_attached_file($post_ID);
            $filename = $file_path ? basename($file_path) : $post->post_title;
            $message = sprintf(
                'Media deleted: %s (ID: %d) by user %s',
                $filename,
                $post_ID,
                $user->user_login
            );
        } else {
            $message = sprintf(
                '%s deleted: %s (ID: %d) by user %s',
                $post_type_name,
                $post->post_title,
                $post_ID,
                $user->user_login
            );
        }
    
        $this->log_activity($message);
    }
    
    

    public function log_trash_post($post_ID) {
        if (!$this->is_cron_allowed() && defined('DOING_CRON') && DOING_CRON) {
            return;
        }
    
        // Ignore customizer and autosave-related trashes
        if (wp_is_post_autosave($post_ID) || wp_is_post_revision($post_ID) || is_customize_preview()) {
            return;
        }
    
        $user = wp_get_current_user();
        $post = get_post($post_ID);
        $post_type_obj = get_post_type_object($post->post_type);
        $post_type_name = !empty($post_type_obj) ? $post_type_obj->labels->singular_name : 'Post';
    
        $message = sprintf(
            '%s trashed: %s (ID: %d) by user %s',
            $post_type_name,
            $post->post_title,
            $post_ID,
            $user->user_login
        );
        $this->log_activity($message);
    }
    
    public function log_option_update($option, $old_value, $value) {
        if (!$this->is_cron_allowed() && defined('DOING_CRON') && DOING_CRON) {
            return;
        }
    
        // Check if we should include transients
        if (!$this->is_transients_allowed()) {
            if (strpos($option, '_transient_') === 0 || strpos($option, '_site_transient_') === 0) {
                return; // Skip logging transient updates
            }
        }
    
        // Get excluded options from settings
        $excluded_options = get_option('activity_logger_excluded_options', '');
        $excluded_options = array_map('trim', explode(',', $excluded_options)); // Convert to array
    
        foreach ($excluded_options as $excluded_option) {
            if (strpos($option, $excluded_option) === 0) {
                return; // Skip logging this option update
            }
        }
    
        $user = wp_get_current_user();
    
        $message = sprintf(
            'Option updated: %s by user %s',
            $option,
            $user->user_login
        );
        $this->log_activity($message);
    }
    

    public function log_plugin_activity($plugin, $network_wide) {
        if (!$this->is_cron_allowed() && defined('DOING_CRON') && DOING_CRON) {
            return;
        }

        $user = wp_get_current_user();

        $action = current_action() == 'activated_plugin' ? 'activated' : 'deactivated';
        $message = sprintf(
            'Plugin %s: %s by user %s',
            $action,
            $plugin,
            $user->user_login
        );
        $this->log_activity($message);
    }

    private function log_activity($message, $user_login = null) {
        global $wpdb;
    
        // If $user_login is not passed, fallback to wp_get_current_user()
        if ($user_login === null) {
            $user = wp_get_current_user();
            $user_login = is_user_logged_in() ? $user->user_login : 'Guest';
        }
    
        // Insert into the database
        $wpdb->insert(
            $this->table_name,
            [
                'username' => $user_login,
                'action' => $message,
                'log_time' => current_time('mysql')
            ],
            [
                '%s',
                '%s',
                '%s'
            ]
        );
    }

    // Function to delete log entries (single or bulk)
    public function delete_log_entry() {
        if (!current_user_can('manage_options')) {
            wp_die('You do not have sufficient permissions to access this page.');
        }

        global $wpdb;

        // Handle bulk delete
        if (isset($_POST['bulk_delete']) && !empty($_POST['log_ids'])) {
            check_admin_referer('bulk_delete_logs');
            $log_ids = array_map('intval', $_POST['log_ids']);
            foreach ($log_ids as $log_id) {
                $wpdb->delete($this->table_name, ['id' => $log_id], ['%d']);
            }

            wp_redirect(admin_url('admin.php?page=activity-logger&log_deleted=true&bulk=true'));
            exit;
        }

        // Handle single delete
        if (isset($_GET['log_id']) && check_admin_referer('delete_log_' . $_GET['log_id'])) {
            $log_id = intval($_GET['log_id']);
            $wpdb->delete($this->table_name, ['id' => $log_id], ['%d']);

            wp_redirect(admin_url('admin.php?page=activity-logger&log_deleted=true'));
            exit;
        }
    }

    public function add_admin_menu() {
        add_menu_page(
            'Activity Logger',
            'Activity Logs',
            'manage_options',
            'activity-logger',
            [$this, 'display_logs_page'],
            'dashicons-list-view'
        );

        add_submenu_page(
            'activity-logger',
            'Activity Logger Settings',
            'Settings',
            'manage_options',
            'activity-logger-settings',
            [$this, 'display_settings_page']
        );

        add_submenu_page(
            'activity-logger',
            'Search Activity Logs',
            'Search Logs',
            'manage_options',
            'activity-logger-search',
            [$this, 'display_search_logs_page']
        );

        add_submenu_page(
            'activity-logger',
            'Export Logs',
            'Export Logs',
            'manage_options',
            'activity-logger-export',
            [$this, 'display_export_logs_page']
        );
        
        
    }

    public function display_logs_page() {
        global $wpdb;
        $logs = $wpdb->get_results("SELECT * FROM {$this->table_name} ORDER BY log_time DESC", ARRAY_A);
    
        echo '<div class="wrap">';
        echo '<h1>Activity Logs</h1>';
    
        if (isset($_GET['log_deleted']) && $_GET['log_deleted'] === 'true') {
            if (isset($_GET['bulk']) && $_GET['bulk'] === 'true') {
                echo '<div class="updated notice is-dismissible"><p>Selected log entries deleted successfully.</p></div>';
            } else {
                echo '<div class="updated notice is-dismissible"><p>Log entry deleted successfully.</p></div>';
            }
        }
    
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field('bulk_delete_logs');
        echo '<input type="hidden" name="action" value="activity_logger_delete_log">';
    
        // Bulk action dropdown
        echo '<div class="tablenav top">';
        echo '<div class="alignleft actions">';
        echo '<select name="bulk_action">';
        echo '<option value="">Bulk Actions</option>';
        echo '<option value="delete">Delete</option>';
        echo '</select>';
        echo '<input type="submit" name="bulk_delete" id="doaction" class="button action" value="Apply">';
        echo '</div>';
        echo '</div>';
    
        // Corrected table structure
        echo '<table class="widefat fixed" cellspacing="0">
                <thead>
                    <tr>
                        <th scope="col" class="manage-column column-cb activity-logger__check-column activity-logger__check-column--header"><input class="activity-logger__checkbox" type="checkbox" id="select-all-logs" /></th>
                        <th scope="col">ID</th>
                        <th scope="col">Username</th>
                        <th scope="col">Action</th>
                        <th scope="col">Log Time</th>
                        <th scope="col">Actions</th>
                    </tr>
                </thead>
                <tbody>';
    
        foreach ($logs as $log) {
            $delete_url = wp_nonce_url(admin_url('admin-post.php?action=activity_logger_delete_log&log_id=' . $log['id']), 'delete_log_' . $log['id']);
            echo '<tr>
                    <td class="activity-logger__check-column"><input type="checkbox" name="log_ids[]" value="' . esc_attr($log['id']) . '" /></td>
                    <td>' . esc_html($log['id']) . '</td>
                    <td>' . esc_html($log['username']) . '</td>
                    <td>' . esc_html($log['action']) . '</td>
                    <td>' . esc_html($log['log_time']) . '</td>
                    <td><a href="' . esc_url($delete_url) . '" class="button button-secondary">Delete</a></td>
                  </tr>';
        }
    
        echo '</tbody></table>';
        echo '</form>';
        echo '</div>';
    }
    
    public function display_settings_page() {
        if (isset($_POST['save_activity_logger_settings'])) {
            update_option('activity_logger_include_cron', isset($_POST['activity_logger_include_cron']) ? '1' : '0');
            update_option('activity_logger_include_transients', isset($_POST['activity_logger_include_transients']) ? '1' : '0');
            
            // Save excluded options
            $excluded_options = sanitize_text_field($_POST['activity_logger_excluded_options']);
            update_option('activity_logger_excluded_options', $excluded_options);
    
            echo '<div id="message" class="updated notice is-dismissible"><p>Settings saved.</p></div>';
        }
    
        $include_cron = get_option('activity_logger_include_cron', '0');
        $include_transients = get_option('activity_logger_include_transients', '1');
        $excluded_options = get_option('activity_logger_excluded_options', ''); // Get saved excluded options
    
        echo '<div class="wrap">';
        echo '<h1>Activity Logger Settings</h1>';
        echo '<form method="post">';
        echo '<table class="form-table">
                <tr valign="top">
                    <th scope="row">Include Cron Events in Logs</th>
                    <td><input type="checkbox" name="activity_logger_include_cron" value="1" ' . checked(1, $include_cron, false) . ' /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Include Transient Option Updates in Logs</th>
                    <td><input type="checkbox" name="activity_logger_include_transients" value="1" ' . checked(1, $include_transients, false) . ' /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Excluded Option Names</th>
                    <td><textarea name="activity_logger_excluded_options" rows="5" cols="50">' . esc_textarea($excluded_options) . '</textarea>
                    <p class="description">Enter option names or prefixes to exclude from logs, separated by commas (e.g., edd_sl_, ninja_forms_, woocommerce_).</p></td>
                </tr>
              </table>';
        echo '<p class="submit"><input type="submit" name="save_activity_logger_settings" class="button-primary" value="Save Changes" /></p>';
        echo '</form>';
        echo '</div>';
    }    

    public function display_search_logs_page() {
        global $wpdb;
    
        // Initialize filters
        $search_query = isset($_GET['s']) ? sanitize_text_field($_GET['s']) : '';
        $user_filter = isset($_GET['user_filter']) ? sanitize_text_field($_GET['user_filter']) : '';
        $action_filter = isset($_GET['action_type']) ? sanitize_text_field($_GET['action_type']) : '';
        $start_date = isset($_GET['start_date']) ? sanitize_text_field($_GET['start_date']) : '';
        $end_date = isset($_GET['end_date']) ? sanitize_text_field($_GET['end_date']) : '';
    
        // Build the SQL query with filters
        $sql = "SELECT * FROM {$this->table_name} WHERE 1=1";
        
        if ($search_query) {
            $sql .= $wpdb->prepare(" AND (username LIKE %s OR action LIKE %s)", '%' . $search_query . '%', '%' . $search_query . '%');
        }
    
        if ($user_filter) {
            $sql .= $wpdb->prepare(" AND username = %s", $user_filter);
        }
    
        if ($action_filter) {
            $sql .= $wpdb->prepare(" AND action LIKE %s", '%' . $action_filter . '%');
        }
    
        if ($start_date && $end_date) {
            $sql .= $wpdb->prepare(" AND log_time BETWEEN %s AND %s", $start_date, $end_date);
        }
    
        $sql .= " ORDER BY log_time DESC";
    
        $logs = $wpdb->get_results($sql, ARRAY_A);
    
        // Get distinct usernames from the log table for the dropdown
        $distinct_users = $wpdb->get_results("SELECT DISTINCT username FROM {$this->table_name} ORDER BY username ASC", ARRAY_A);
    
        echo '<div class="wrap">';
        echo '<h1>Search Activity Logs</h1>';
    
        // Search and filter form
        echo '<form method="get" action="">';
        echo '<input type="hidden" name="page" value="activity-logger-search">';
        
        echo '<p>';
        echo 'Search: <input type="text" name="s" value="' . esc_attr($search_query) . '" />';
    
        // User filter dropdown
        echo ' User: <select name="user_filter">';
        echo '<option value="">All Users</option>';
        foreach ($distinct_users as $user) {
            echo '<option value="' . esc_attr($user['username']) . '"' . selected($user_filter, $user['username'], false) . '>' . esc_html($user['username']) . '</option>';
        }
        echo '</select>';
    
        echo ' Action: <select name="action_type">';
        echo '<option value="">All Actions</option>';
        echo '<option value="created"' . selected($action_filter, 'created', false) . '>Created</option>';
        echo '<option value="updated"' . selected($action_filter, 'updated', false) . '>Updated</option>';
        echo '<option value="trashed"' . selected($action_filter, 'trashed', false) . '>Trashed</option>';
        echo '<option value="deleted"' . selected($action_filter, 'deleted', false) . '>Deleted</option>';
        echo '</select>';
        
        echo ' Date Range: <input type="date" name="start_date" value="' . esc_attr($start_date) . '" />';
        echo ' to <input type="date" name="end_date" value="' . esc_attr($end_date) . '" />';
        
        echo ' <input type="submit" value="Filter" class="button-primary" />';
        echo '</p>';
        echo '</form>';
    
        echo '<table class="widefat fixed" cellspacing="0">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Action</th>
                        <th>Log Time</th>
                    </tr>
                </thead>
                <tbody>';
    
        if (!empty($logs)) {
            foreach ($logs as $log) {
                echo '<tr>
                        <td>' . esc_html($log['id']) . '</td>
                        <td>' . esc_html($log['username']) . '</td>
                        <td>' . esc_html($log['action']) . '</td>
                        <td>' . esc_html($log['log_time']) . '</td>
                      </tr>';
            }
        } else {
            echo '<tr><td colspan="4">No logs found</td></tr>';
        }
    
        echo '</tbody></table>';
        echo '</div>';
    }    

    public function display_export_logs_page() {
        // Check if the form has been submitted
        if (isset($_POST['export_logs'])) {
            // Get selected fields
            $fields = isset($_POST['fields']) ? $_POST['fields'] : [];
    
            // Validate fields
            if (empty($fields)) {
                echo '<div class="error"><p>Please select at least one field to export.</p></div>';
            } else {
                // Call the export function
                $this->export_logs_csv($fields);
            }
        }
    
        // Display the export settings form
        echo '<div class="wrap">';
        echo '<h1>Export Activity Logs</h1>';
        echo '<form method="post">';
        
        echo '<h3>Select Fields to Export</h3>';
        echo '<p><input type="checkbox" name="fields[]" value="id" /> ID</p>';
        echo '<p><input type="checkbox" name="fields[]" value="username" /> Username</p>';
        echo '<p><input type="checkbox" name="fields[]" value="action" /> Action</p>';
        echo '<p><input type="checkbox" name="fields[]" value="log_time" /> Log Time</p>';
        
        echo '<h3>Select Format</h3>';
        echo '<p><input type="radio" name="format" value="csv" checked /> CSV</p>';
        // Optionally add more formats later like JSON, XML
    
        echo '<p><input type="submit" name="export_logs" class="button-primary" value="Export Logs" /></p>';
        
        echo '</form>';
        echo '</div>';
    }    

    private function is_cron_allowed() {
        return get_option('activity_logger_include_cron', '0') === '1';
    }

    private function is_transients_allowed() {
        return get_option('activity_logger_include_transients', '1') === '1';
    }

    public function export_logs_csv($fields) {
        if (!current_user_can('manage_options')) {
            wp_die('You do not have sufficient permissions to access this page.');
        }
    
        // Fetch logs
        global $wpdb;
        $logs = $wpdb->get_results("SELECT * FROM {$this->table_name} ORDER BY log_time DESC", ARRAY_A);
    
        // Set CSV headers
        $filename = 'activity_logs_' . date('Y-m-d_H-i-s') . '.csv';
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename=' . $filename);
        header('Pragma: no-cache');
        header('Expires: 0');
    
        // Open output stream
        $output = fopen('php://output', 'w');
    
        // Build the header row based on selected fields
        $header_row = [];
        if (in_array('id', $fields)) {
            $header_row[] = 'ID';
        }
        if (in_array('username', $fields)) {
            $header_row[] = 'Username';
        }
        if (in_array('action', $fields)) {
            $header_row[] = 'Action';
        }
        if (in_array('log_time', $fields)) {
            $header_row[] = 'Log Time';
        }
    
        // Output the column headings
        fputcsv($output, $header_row);
    
        // Loop over logs and output CSV rows
        foreach ($logs as $log) {
            $row = [];
            if (in_array('id', $fields)) {
                $row[] = $log['id'];
            }
            if (in_array('username', $fields)) {
                $row[] = $log['username'];
            }
            if (in_array('action', $fields)) {
                $row[] = $log['action'];
            }
            if (in_array('log_time', $fields)) {
                $row[] = $log['log_time'];
            }
    
            fputcsv($output, $row);
        }
    
        fclose($output);
        exit;
    }
    
}

new Activity_Logger();
