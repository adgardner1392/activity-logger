=== Activity Logger ===
Contributors: Adam Gardner
Tags: logging, cms, activity, WordPress
Requires at least: 5.0
Tested up to: 6.6.2
Stable tag: 1.1.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Logs all activity within the CMS by logged-in users. Allows for user-defined exclusions, filtering, and log exports.

== Description ==

Activity Logger is a plugin that helps you keep track of all activities carried out by logged-in users, including post/page edits, plugin activations, and more. You can also exclude certain types of updates from being logged and filter logs through an admin interface.

**Key Features:**
- Logs post/page creation, updates, deletions, and media uploads.
- Tracks plugin activation, deactivation, and option updates.
- Allows excluding specific options from logging via the settings interface.
- Logs user login, logout, profile updates, and password resets.
- Supports bulk and individual deletion of logs.
- Search and filter logs by username, action, post type, or date.
- Export logs in CSV format.
- Settings page for defining exclusions (option names or prefixes).
- Custom admin menu for easy navigation and configuration of logs.

== Installation ==

1. Upload the `activity-logger` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Navigate to the **Activity Logs** menu in the admin to view logs, configure settings, and export logs.

== Frequently Asked Questions ==

= Does this plugin work with the latest version of WordPress? =
Yes, it has been tested with the latest version of WordPress.

= How do I exclude specific options from logging? =
You can exclude certain options or prefixes from being logged by adding them to the **Excluded Option Names** field in the plugin's settings. Simply input the option names or prefixes (comma-separated) that you want to exclude from logs. For example, to exclude all options starting with `edd_sl_`, add `edd_sl_` to the exclusions list.

= Can I search or filter the activity logs? =
Yes, the plugin provides a search and filter interface where you can filter logs by username, action (created, updated, deleted), post type, and date range. You can also search for specific terms.

= Can I export the logs? =
Yes, you can export the logs to a CSV file. The export functionality is available under a separate **Export Logs** menu.

= Can I delete individual or multiple log entries? =
Yes, you can either delete individual log entries or select multiple entries for bulk deletion using the checkbox and dropdown on the **Activity Logs** page.

== Roadmap ==

**Upcoming Features:**
- **Improved Reporting**: A detailed reporting interface for visualising activity data with charts and graphs.
- **User Roles**: Add user-role-based filtering to log activity based on specific user roles.
- **Notifications**: Email notifications for specific logged actions (e.g., plugin activation, critical post updates).
- **Advanced Search**: Enhanced search functionality with additional filters like IP address, location, and device.
- **Log Retention Settings**: Ability to define log retention periods and automatically purge older logs.
- **REST API Support**: Adding REST API endpoints to access and manage logs programmatically.
- **Multisite Compatibility**: Ensure full multisite compatibility with network-level logging and export functionality.

We welcome feedback and suggestions for new features!

== Changelog ==

= 1.1.1 = 
* Removed language domain path reference.

= 1.1 = 
* Security updates: nonce validation and input sanitization for better security.
* Implemented caching for logs to improve performance.
* Fixed issues with date filtering in search logs.
* Prefill search filters with selected values on results page.
* Refactored SQL queries to ensure proper preparation and avoid security risks.
* Added detailed logging for user profile updates and password resets.
* Minor UI improvements in the admin area for better usability.
* Removed language translation placeholder.

= 1.0 =
* Initial release.
* Added functionality to log post and page activities.
* Added plugin activation, deactivation, and option update logging.
* User login, logout, profile updates, and password reset logging.
* Bulk and individual deletion of logs.
* Search and filter logs by user, action, post type, and date.
* Export logs as CSV.
* Added settings to exclude specific option names from being logged.
