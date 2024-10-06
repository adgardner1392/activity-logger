<?php
/*
Plugin Name: Activity Logger
Plugin URI: https://github.com/adgardner1392/activity-logger
Description: Logs all activity within the CMS by logged-in users (e.g., editing posts, deleting posts, changing settings), with user-defined exclusions, filtering, and log export functionality.
Version: 1.1.1
Author: Adam Gardner
Author URI: https://github.com/adgardner1392
License: GPLv2 or later
Text Domain: activity-logger
*/

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly
}

global $wpdb;
if ( ! defined( 'ACTIVITY_LOGGER_TABLE_NAME' ) ) {
    define( 'ACTIVITY_LOGGER_TABLE_NAME', $wpdb->prefix . 'activity_log' );
}

class Activity_Logger {

    // Cache key constants
    private $logs_cache_key       = 'activity_logger_logs';
    private $usernames_cache_key  = 'activity_logger_usernames';

    // Declare a global variable to store the username
    private $logged_in_user_login = null;

    public function __construct() {
        $this->create_log_table();

        add_action( 'wp_insert_post', [ $this, 'log_post_activity' ], 10, 3 );
        add_action( 'delete_post', [ $this, 'log_delete_post' ], 10, 1 );
        add_action( 'add_attachment', [ $this, 'log_upload_attachment' ], 10, 1 );
        add_action( 'updated_option', [ $this, 'log_option_update' ], 10, 3 );
        add_action( 'activated_plugin', [ $this, 'log_plugin_activity' ], 10, 2 );
        add_action( 'deactivated_plugin', [ $this, 'log_plugin_activity' ], 10, 2 );
        add_action( 'wp_trash_post', [ $this, 'log_trash_post' ], 10, 1 );
        add_action( 'admin_menu', [ $this, 'add_admin_menu' ] );

        // User profile and authentication logging
        add_action( 'profile_update', [ $this, 'log_profile_update' ], 10, 2 );
        add_action( 'wp_login', [ $this, 'log_user_login' ], 10, 2 );
        // Capture user info before logout
        add_action( 'set_current_user', [ $this, 'capture_user_login' ] );
        // Hook into logout event
        add_action( 'wp_logout', [ $this, 'log_user_logout' ] );
        add_action( 'after_password_reset', [ $this, 'log_password_reset' ], 10, 2 );

        // Enqueue scripts and styles
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_admin_assets' ] );

        // Handle export logs action
        add_action( 'admin_post_activity_logger_export_logs', [ $this, 'export_logs_csv' ] );
        // Handle delete log action
        add_action( 'admin_post_activity_logger_delete_log', [ $this, 'delete_log_entry' ] );
    }

    // Enqueue JavaScript and CSS files
    public function enqueue_admin_assets() {
        // Only enqueue on the plugin's admin page
        $screen = get_current_screen();
        if ( $screen->id !== 'toplevel_page_activity-logger' ) {
            return;
        }

        // Enqueue JavaScript file
        wp_enqueue_script(
            'activity-logger-admin-js',
            plugin_dir_url( __FILE__ ) . 'js/admin.js',
            [ 'jquery' ], // Add dependencies if necessary
            '1.0',
            true // Enqueue in the footer
        );

        // Enqueue optional CSS file
        wp_enqueue_style(
            'activity-logger-admin-css',
            plugin_dir_url( __FILE__ ) . 'css/admin.css',
            [],
            '1.0'
        );
    }

    private function create_log_table() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        $table_name = ACTIVITY_LOGGER_TABLE_NAME;

        // Use a transient to check if the table needs to be created.
        $cache_key    = 'activity_log_table_exists';
        $table_exists = wp_cache_get( $cache_key );

        if ( $table_exists === false ) {
            // Prepare the SQL query safely
            $like = $wpdb->esc_like( $table_name );
            $sql  = $wpdb->prepare( "SHOW TABLES LIKE %s", $like );
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery -- Direct query is required for retrieving column information from the database.
            $table_exists = ( $wpdb->get_var( $sql ) === $table_name );

            // Cache the result for 12 hours to avoid redundant queries.
            wp_cache_set( $cache_key, $table_exists, '', 12 * HOUR_IN_SECONDS );
        }

        // If the table doesn't exist, create it.
        if ( ! $table_exists ) {
            $sql = "CREATE TABLE {$table_name} (
                id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
                username VARCHAR(60) NOT NULL,
                action TEXT NOT NULL,
                log_time DATETIME NOT NULL,
                PRIMARY KEY (id)
            ) $charset_collate;";

            require_once ABSPATH . 'wp-admin/includes/upgrade.php';
            dbDelta( $sql );

            // Invalidate cache now that the table is created.
            wp_cache_set( $cache_key, true, '', 12 * HOUR_IN_SECONDS );
        }

        // Check the 'username' column type and modify if necessary.
        $column_cache_key = 'activity_log_username_column';
        $column_info      = wp_cache_get( $column_cache_key );

        if ( $column_info === false ) {
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is safe and constant.
            $sql = $wpdb->prepare( "SHOW COLUMNS FROM {$table_name} LIKE %s", 'username' );
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery -- Direct query is required for retrieving column information from the database.
            $column_info = $wpdb->get_row( $sql );
            wp_cache_set( $column_cache_key, $column_info, '', 12 * HOUR_IN_SECONDS );
        }

        if ( $column_info && strpos( $column_info->Type, 'varchar' ) === false ) {
            $sql = "ALTER TABLE {$table_name} MODIFY username VARCHAR(60) NOT NULL;";
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery -- Direct query is required for retrieving column information from the database.
            $wpdb->query( $sql );
            wp_cache_delete( $column_cache_key ); // Clear cache after modifying the table.
        }
    }

    public function log_post_activity( $post_ID, $post, $update ) {
        if ( ! $this->is_cron_allowed() && defined( 'DOING_CRON' ) && DOING_CRON ) {
            return;
        }

        // Ignore autosaves, revisions, customizer changes, and posts being trashed
        if ( wp_is_post_autosave( $post_ID ) || wp_is_post_revision( $post_ID ) || is_customize_preview() || $post->post_status === 'trash' ) {
            return;
        }

        $user           = wp_get_current_user();
        $post_type_obj  = get_post_type_object( $post->post_type );
        $post_type_name = ! empty( $post_type_obj ) ? $post_type_obj->labels->singular_name : 'Post';

        $action     = $update ? 'updated' : 'created';
        $post_title = ! empty( $post->post_title ) ? $post->post_title : '(no title)';

        $message = sprintf(
            '%s %s: %s (ID: %d) by user %s',
            $post_type_name,
            $action,
            $post_title,
            $post_ID,
            $user->user_login
        );

        $this->log_activity( $message );
    }

    public function log_profile_update( $user_id, $old_user_data ) {
        $user = get_userdata( $user_id );

        // Check which fields were updated
        $changes = [];
        if ( $old_user_data->user_email !== $user->user_email ) {
            $changes[] = 'email';
        }
        if ( $old_user_data->first_name !== $user->first_name ) {
            $changes[] = 'first name';
        }
        if ( $old_user_data->last_name !== $user->last_name ) {
            $changes[] = 'last name';
        }

        // Only log if there were changes
        if ( ! empty( $changes ) ) {
            $message = sprintf(
                'Profile updated: %s (ID: %d) changed %s by user %s',
                $user->user_login,
                $user->ID,
                implode( ', ', $changes ),
                wp_get_current_user()->user_login
            );
            $this->log_activity( $message );
        }
    }

    public function log_user_login( $user_login, $user ) {
        $message = sprintf(
            'User logged in: %s (ID: %d)',
            $user_login,
            $user->ID
        );
        $this->log_activity( $message, $user_login );
    }

    // Capture the current user's login before the logout happens
    public function capture_user_login() {
        $user = wp_get_current_user();
        if ( $user && $user->ID ) {
            $this->logged_in_user_login = $user->user_login;
        }
    }

    // Log user logout using the captured login
    public function log_user_logout() {
        if ( $this->logged_in_user_login ) {
            $message = sprintf(
                'User logged out: %s',
                $this->logged_in_user_login
            );
            $this->log_activity( $message, $this->logged_in_user_login );
        }
    }

    public function log_password_reset( $user, $new_password ) {
        $message = sprintf(
            'Password reset: %s (ID: %d)',
            $user->user_login,
            $user->ID
        );
        $this->log_activity( $message );
    }

    public function log_upload_attachment( $post_ID ) {
        $user = wp_get_current_user();

        // Retrieve the full file path and get the filename with extension
        $file_path = get_attached_file( $post_ID );
        $filename  = $file_path ? basename( $file_path ) : get_the_title( $post_ID ); // Fallback to post title if no file path

        $message = sprintf(
            'Media uploaded: %s (ID: %d) by user %s',
            $filename,
            $post_ID,
            $user->user_login
        );

        $this->log_activity( $message );
    }

    public function log_delete_post( $post_ID ) {
        if ( ! $this->is_cron_allowed() && defined( 'DOING_CRON' ) && DOING_CRON ) {
            return;
        }

        // Ignore customizer and autosave-related deletions
        if ( wp_is_post_autosave( $post_ID ) || wp_is_post_revision( $post_ID ) || is_customize_preview() ) {
            return;
        }

        $user           = wp_get_current_user();
        $post           = get_post( $post_ID );
        $post_type_obj  = get_post_type_object( $post->post_type );
        $post_type_name = ! empty( $post_type_obj ) ? $post_type_obj->labels->singular_name : 'Post';

        if ( $post->post_type === 'attachment' ) {
            $file_path = get_attached_file( $post_ID );
            $filename  = $file_path ? basename( $file_path ) : $post->post_title;
            $message   = sprintf(
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

        $this->log_activity( $message );
    }

    public function log_trash_post( $post_ID ) {
        if ( ! $this->is_cron_allowed() && defined( 'DOING_CRON' ) && DOING_CRON ) {
            return;
        }

        // Ignore customizer and autosave-related trashes
        if ( wp_is_post_autosave( $post_ID ) || wp_is_post_revision( $post_ID ) || is_customize_preview() ) {
            return;
        }

        $user           = wp_get_current_user();
        $post           = get_post( $post_ID );
        $post_type_obj  = get_post_type_object( $post->post_type );
        $post_type_name = ! empty( $post_type_obj ) ? $post_type_obj->labels->singular_name : 'Post';

        $message = sprintf(
            '%s trashed: %s (ID: %d) by user %s',
            $post_type_name,
            $post->post_title,
            $post_ID,
            $user->user_login
        );
        $this->log_activity( $message );
    }

    public function log_option_update( $option, $old_value, $value ) {
        if ( ! $this->is_cron_allowed() && defined( 'DOING_CRON' ) && DOING_CRON ) {
            return;
        }

        // Check if we should include transients
        if ( ! $this->is_transients_allowed() ) {
            if ( strpos( $option, '_transient_' ) === 0 || strpos( $option, '_site_transient_' ) === 0 ) {
                return; // Skip logging transient updates
            }
        }

        // Get excluded options from settings
        $excluded_options = get_option( 'activity_logger_excluded_options', '' );
        $excluded_options = array_map( 'trim', explode( ',', $excluded_options ) ); // Convert to array

        foreach ( $excluded_options as $excluded_option ) {
            if ( strpos( $option, $excluded_option ) === 0 ) {
                return; // Skip logging this option update
            }
        }

        $user = wp_get_current_user();

        $message = sprintf(
            'Option updated: %s by user %s',
            $option,
            $user->user_login
        );
        $this->log_activity( $message );
    }

    public function log_plugin_activity( $plugin, $network_wide ) {
        if ( ! $this->is_cron_allowed() && defined( 'DOING_CRON' ) && DOING_CRON ) {
            return;
        }

        $user = wp_get_current_user();

        $action  = current_action() == 'activated_plugin' ? 'activated' : 'deactivated';
        $message = sprintf(
            'Plugin %s: %s by user %s',
            $action,
            $plugin,
            $user->user_login
        );
        $this->log_activity( $message );
    }

    private function log_activity( $message, $user_login = null ) {
        global $wpdb;

        // If $user_login is not passed, fallback to wp_get_current_user()
        if ( $user_login === null ) {
            $user       = wp_get_current_user();
            $user_login = is_user_logged_in() ? $user->user_login : 'Guest';
        }

        // Invalidate cache after adding a new log
        wp_cache_delete( $this->logs_cache_key );

        // Insert into the database
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Direct query is required for retrieving column information from the database.
        $wpdb->insert(
            ACTIVITY_LOGGER_TABLE_NAME,
            [
                'username' => $user_login,
                'action'   => $message,
                'log_time' => current_time( 'mysql' ),
            ],
            [
                '%s',
                '%s',
                '%s',
            ]
        );
    }

    // Function to delete log entries (single or bulk)
    public function delete_log_entry() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'You do not have sufficient permissions to access this page.' );
        }

        global $wpdb;

        // Handle bulk delete
        if ( isset( $_POST['bulk_delete'] ) && ! empty( $_POST['log_ids'] ) ) {
            check_admin_referer( 'bulk_delete_logs_nonce' );
            $log_ids = array_map( 'intval', $_POST['log_ids'] );

            // Prepare placeholders for IN clause
            $placeholders = implode( ',', array_fill( 0, count( $log_ids ), '%d' ) );

            $sql = "DELETE FROM " . ACTIVITY_LOGGER_TABLE_NAME . " WHERE id IN ($placeholders)";
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery -- Direct database call is necessary, and query is safely prepared with $wpdb->prepare().
            $wpdb->query( $wpdb->prepare( $sql, $log_ids ) );

            // Invalidate cache after deletion
            wp_cache_delete( $this->logs_cache_key );

            // Generate a nonce for the redirect
            $redirect_nonce = wp_create_nonce( 'log_deleted_nonce' );
            wp_redirect( admin_url( 'admin.php?page=activity-logger&log_deleted=true&_wpnonce=' . $redirect_nonce ) );

            exit;
        }

        // Handle single delete
        if ( isset( $_GET['log_id'] ) && check_admin_referer( 'delete_log_' . intval( wp_unslash( $_GET['log_id'] ) ) ) ) {
            $log_id = intval( wp_unslash( $_GET['log_id'] ) );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Direct query with $wpdb->delete() is required for deleting from a custom table, and the table name is safe and constant.
            $wpdb->delete( ACTIVITY_LOGGER_TABLE_NAME, [ 'id' => $log_id ], [ '%d' ] );

            wp_redirect( admin_url( 'admin.php?page=activity-logger&log_deleted=true' ) );
            exit;
        }
    }

    public function add_admin_menu() {
        add_menu_page(
            __( 'Activity Logger', 'activity-logger' ), // Translatable plugin name
            __( 'Activity Logs', 'activity-logger' ),   // Translatable menu title
            'manage_options',
            'activity-logger',
            [ $this, 'display_logs_page' ],
            'dashicons-list-view'
        );
        

        add_submenu_page(
            'activity-logger',
            'Activity Logger Settings',
            'Settings',
            'manage_options',
            'activity-logger-settings',
            [ $this, 'display_settings_page' ]
        );

        add_submenu_page(
            'activity-logger',
            'Search Activity Logs',
            'Search Logs',
            'manage_options',
            'activity-logger-search',
            [ $this, 'display_search_logs_page' ]
        );

        add_submenu_page(
            'activity-logger',
            'Export Logs',
            'Export Logs',
            'manage_options',
            'activity-logger-export',
            [ $this, 'display_export_logs_page' ]
        );
    }

    public function display_logs_page() {
        global $wpdb;

        // Try to retrieve the logs from cache
        $logs = wp_cache_get( $this->logs_cache_key );
        if ( $logs === false ) {
            // If not cached, fetch logs from the database
            $sql  = "SELECT * FROM " . ACTIVITY_LOGGER_TABLE_NAME . " ORDER BY log_time DESC";
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery -- Direct query required for fetching results from custom table, no WordPress function available.
            $logs = $wpdb->get_results( $sql, ARRAY_A );
            wp_cache_set( $this->logs_cache_key, $logs );
        }

        echo '<div class="wrap">';
        echo '<h1>Activity Logs</h1>';


        if ( isset( $_GET['log_deleted'] ) && $_GET['log_deleted'] === 'true' && isset( $_GET['_wpnonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ), 'log_deleted_nonce' ) ) {
            if ( isset( $_GET['bulk'] ) && $_GET['bulk'] === 'true' ) {
                echo '<div class="updated notice is-dismissible"><p>Selected log entries deleted successfully.</p></div>';
            } else {
                echo '<div class="updated notice is-dismissible"><p>Log entry deleted successfully.</p></div>';
            }
        }

        echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
        wp_nonce_field( 'bulk_delete_logs_nonce' );
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

        // Table structure
        echo '<table class="widefat fixed" cellspacing="0">
                <thead>
                    <tr>
                        <th scope="col" class="manage-column column-cb check-column"><input type="checkbox" id="select-all-logs" /></th>
                        <th scope="col">ID</th>
                        <th scope="col">Username</th>
                        <th scope="col">Action</th>
                        <th scope="col">Log Time</th>
                        <th scope="col">Actions</th>
                    </tr>
                </thead>
                <tbody>';

        foreach ( $logs as $log ) {
            $delete_url = wp_nonce_url( admin_url( 'admin-post.php?action=activity_logger_delete_log&log_id=' . $log['id'] ), 'delete_log_' . $log['id'] );
            echo '<tr>
                    <th scope="row" class="check-column"><input type="checkbox" name="log_ids[]" value="' . esc_attr( $log['id'] ) . '" /></th>
                    <td>' . esc_html( $log['id'] ) . '</td>
                    <td>' . esc_html( $log['username'] ) . '</td>
                    <td>' . esc_html( $log['action'] ) . '</td>
                    <td>' . esc_html( $log['log_time'] ) . '</td>
                    <td><a href="' . esc_url( $delete_url ) . '" class="button button-secondary">Delete</a></td>
                  </tr>';
        }

        echo '</tbody></table>';
        echo '</form>';
        echo '</div>';
    }

    public function display_settings_page() {
        if ( isset( $_POST['save_activity_logger_settings'] ) ) {
            check_admin_referer( 'activity_logger_settings_nonce' );
            update_option( 'activity_logger_include_cron', isset( $_POST['activity_logger_include_cron'] ) ? '1' : '0' );
            update_option( 'activity_logger_include_transients', isset( $_POST['activity_logger_include_transients'] ) ? '1' : '0' );

            // Save excluded options
            $excluded_options = isset( $_POST['activity_logger_excluded_options'] ) ? sanitize_text_field( wp_unslash( $_POST['activity_logger_excluded_options'] ) ) : '';
            update_option( 'activity_logger_excluded_options', $excluded_options );

            echo '<div id="message" class="updated notice is-dismissible"><p>Settings saved.</p></div>';
        }

        $include_cron       = get_option( 'activity_logger_include_cron', '0' );
        $include_transients = get_option( 'activity_logger_include_transients', '1' );
        $excluded_options   = get_option( 'activity_logger_excluded_options', '' );

        echo '<div class="wrap">';
        echo '<h1>Activity Logger Settings</h1>';
        echo '<form method="post">';
        wp_nonce_field( 'activity_logger_settings_nonce' );
        echo '<table class="form-table">
                <tr valign="top">
                    <th scope="row">Include Cron Events in Logs</th>
                    <td><input type="checkbox" name="activity_logger_include_cron" value="1" ' . checked( 1, $include_cron, false ) . ' /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Include Transient Option Updates in Logs</th>
                    <td><input type="checkbox" name="activity_logger_include_transients" value="1" ' . checked( 1, $include_transients, false ) . ' /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Excluded Option Names</th>
                    <td><textarea name="activity_logger_excluded_options" rows="5" cols="50">' . esc_textarea( $excluded_options ) . '</textarea>
                    <p class="description">Enter option names or prefixes to exclude from logs, separated by commas (e.g., edd_sl_, ninja_forms_, woocommerce_).</p></td>
                </tr>
              </table>';
        echo '<p class="submit"><input type="submit" name="save_activity_logger_settings" class="button-primary" value="Save Changes" /></p>';
        echo '</form>';
        echo '</div>';
    }

    public function display_search_logs_page() {
        global $wpdb;
    
        $table_name = ACTIVITY_LOGGER_TABLE_NAME;
    
        // Verify the nonce before processing the form data
        if ( isset( $_GET['_wpnonce'] ) && ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ), 'search_activity_logs' ) ) {
            wp_die( 'Nonce verification failed' );
        }
    
        // Initialize filters
        $search_query  = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '';
        $user_filter   = isset( $_GET['user_filter'] ) ? sanitize_text_field( wp_unslash( $_GET['user_filter'] ) ) : '';
        $action_filter = isset( $_GET['action_type'] ) ? sanitize_text_field( wp_unslash( $_GET['action_type'] ) ) : '';
        $start_date    = isset( $_GET['start_date'] ) ? sanitize_text_field( wp_unslash( $_GET['start_date'] ) ) : '';
        $end_date      = isset( $_GET['end_date'] ) ? sanitize_text_field( wp_unslash( $_GET['end_date'] ) ) : '';
    
        // Prepare date format for SQL query
        if ( $start_date ) {
            $start_date .= ' 00:00:00'; // Start of the day
        }
        if ( $end_date ) {
            $end_date .= ' 23:59:59'; // End of the day
        }
    
        // Base SQL query with placeholders
        $sql        = "SELECT * FROM {$table_name} WHERE 1=1";
        $query_args = [];
    
        // Add conditions dynamically while using placeholders
        if ( $search_query ) {
            $sql         .= " AND (username LIKE %s OR action LIKE %s)";
            $like_query   = '%' . $wpdb->esc_like( $search_query ) . '%';
            $query_args[] = $like_query;
            $query_args[] = $like_query;
        }
    
        if ( $user_filter ) {
            $sql         .= " AND username = %s";
            $query_args[] = $user_filter;
        }
    
        if ( $action_filter ) {
            $sql         .= " AND action LIKE %s";
            $like_action  = '%' . $wpdb->esc_like( $action_filter ) . '%';
            $query_args[] = $like_action;
        }
    
        if ( $start_date && $end_date ) {
            $sql         .= " AND log_time BETWEEN %s AND %s";
            $query_args[] = $start_date;
            $query_args[] = $end_date;
        }
    
        $sql .= " ORDER BY log_time DESC";
    
        // Prepare the SQL query with arguments
        if ( ! empty( $query_args ) ) {
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
            $prepared_sql = $wpdb->prepare( $sql, $query_args );
        } else {
            $prepared_sql = $sql;
        }
    
        // Use cache for logs
        $logs_cache_key = 'activity_logs_' . md5( $prepared_sql );
        $logs           = wp_cache_get( $logs_cache_key );
    
        if ( $logs === false ) {
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery -- Direct query required for retrieving data from custom table, prepared with $wpdb->prepare().
            $logs = $wpdb->get_results( $prepared_sql, ARRAY_A );
            wp_cache_set( $logs_cache_key, $logs );
        }
    
        // Get distinct usernames from cache or database
        $usernames_cache_key = 'distinct_usernames';
        $distinct_users      = wp_cache_get( $usernames_cache_key );
    
        if ( $distinct_users === false ) {
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery -- Direct query required for custom table, no WordPress function available, table name is safe and constant.
            $distinct_users = $wpdb->get_results( "SELECT DISTINCT username FROM {$table_name} ORDER BY username ASC", ARRAY_A ); 
            wp_cache_set( $usernames_cache_key, $distinct_users );
        }
    
        echo '<div class="wrap">';
        echo '<h1>Search Activity Logs</h1>';
    
        // Search and filter form
        echo '<form method="get" action="">';
        echo '<input type="hidden" name="page" value="activity-logger-search">';

        // Add nonce field to the search form
        wp_nonce_field( 'search_activity_logs' );

        echo '<p>';
        echo 'Search: <input type="text" name="s" value="' . esc_attr( $search_query ) . '" />';

        // User filter dropdown
        echo ' User: <select name="user_filter">';
        echo '<option value="">All Users</option>';
        foreach ( $distinct_users as $user ) {
            echo '<option value="' . esc_attr( $user['username'] ) . '"' . selected( $user_filter, $user['username'], false ) . '>' . esc_html( $user['username'] ) . '</option>';
        }
        echo '</select>';

        echo ' Action: <select name="action_type">';
        echo '<option value="">All Actions</option>';
        echo '<option value="created"' . selected( $action_filter, 'created', false ) . '>Created</option>';
        echo '<option value="updated"' . selected( $action_filter, 'updated', false ) . '>Updated</option>';
        echo '<option value="trashed"' . selected( $action_filter, 'trashed', false ) . '>Trashed</option>';
        echo '<option value="deleted"' . selected( $action_filter, 'deleted', false ) . '>Deleted</option>';
        echo '</select>';

        // Prefill date inputs with selected values
        echo ' Date Range: <input type="date" name="start_date" value="' . esc_attr( isset( $_GET['start_date'] ) ? sanitize_text_field(wp_unslash($_GET['start_date'])) : '' ) . '" />';
        echo ' to <input type="date" name="end_date" value="' . esc_attr( isset( $_GET['end_date'] ) ? sanitize_text_field(wp_unslash($_GET['end_date'])) : '' ) . '" />';

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
    
        if ( ! empty( $logs ) ) {
            foreach ( $logs as $log ) {
                echo '<tr>
                        <td>' . esc_html( $log['id'] ) . '</td>
                        <td>' . esc_html( $log['username'] ) . '</td>
                        <td>' . esc_html( $log['action'] ) . '</td>
                        <td>' . esc_html( $log['log_time'] ) . '</td>
                      </tr>';
            }
        } else {
            echo '<tr><td colspan="4">No logs found</td></tr>';
        }
    
        echo '</tbody></table>';
        echo '</div>';
    }
    
    
    public function display_export_logs_page() {
        echo '<div class="wrap">';
        echo '<h1>Export Activity Logs</h1>';
        echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
        echo '<input type="hidden" name="action" value="activity_logger_export_logs">';
        echo '<p><input type="submit" class="button-primary" value="Export All Logs as CSV" /></p>';
        echo '</form>';
        echo '</div>';
    }

    private function is_cron_allowed() {
        return get_option( 'activity_logger_include_cron', '0' ) === '1';
    }

    private function is_transients_allowed() {
        return get_option( 'activity_logger_include_transients', '1' ) === '1';
    }

    public function export_logs_csv() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'You do not have sufficient permissions to access this page.' );
        }
    
        // Initialize WP_Filesystem
        if ( ! function_exists( 'WP_Filesystem' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();
    
        global $wp_filesystem, $wpdb;
    
        $table_name = $wpdb->prefix . 'activity_log';
        $cache_key = 'activity_log_cache';
        $logs = wp_cache_get( $cache_key );
        
        if ( $logs === false ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Direct query required for fetching data from custom table.
            $sql = "SELECT * FROM {$table_name} ORDER BY log_time DESC";
            
            // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery -- Direct query required for fetching data from custom table. Table name is a constant and safe.
            $logs = $wpdb->get_results( $sql, ARRAY_A );
        
            // Set cache for future requests
            wp_cache_set( $cache_key, $logs, '', 12 * HOUR_IN_SECONDS );
        }
    
        // Build the CSV content
        $csv_content = '';
    
        // Add header row
        $header_row = [ 'ID', 'Username', 'Action', 'Log Time' ];
        $csv_content .= $this->array_to_csv_line( $header_row );
    
        // Loop over logs and build CSV rows
        foreach ( $logs as $log ) {
            // Sanitize fields with sanitize_text_field
            $row = [
                sanitize_text_field( $log['id'] ),
                sanitize_text_field( $log['username'] ),
                sanitize_text_field( $log['action'] ),
                sanitize_text_field( $log['log_time'] ),
            ];
            $csv_content .= $this->array_to_csv_line( $row );
        }
    
        // Create a temporary file
        $temp_file = wp_tempnam( 'activity_logs.csv' );
    
        if ( ! $temp_file ) {
            wp_die( 'Could not create temporary file for export.' );
        }
    
        // Write the CSV content to the temporary file using WP_Filesystem
        $wp_filesystem->put_contents( $temp_file, $csv_content, FS_CHMOD_FILE );
    
        // Set headers to trigger file download
        $filename = 'activity_logs_' . gmdate( 'Y-m-d_H-i-s' ) . '.csv';
        header( 'Content-Type: text/csv; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename=' . esc_attr( $filename ) );
        header( 'Content-Length: ' . $wp_filesystem->size( $temp_file ) );
    
        // Read the file content using WP_Filesystem
        $file_content = $wp_filesystem->get_contents( $temp_file );
    
        if ( $file_content === false ) {
            wp_die( 'Could not read temporary file for export.' );
        }
    
        // Output the file content WITHOUT further escaping
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV content is safe and sanitized before output
        echo $file_content;
    
        // Delete the temporary file
        $wp_filesystem->delete( $temp_file );
    
        exit;
    }
    
    // Example CSV line generator
    private function array_to_csv_line( $array ) {
        $escaped_array = array_map( function ( $field ) {
            // Manually handle double quotes for CSV without HTML escaping
            return '"' . str_replace( '"', '""', $field ) . '"';
        }, $array );
    
        return implode( ',', $escaped_array ) . "\n";
    }
    
}

new Activity_Logger();
