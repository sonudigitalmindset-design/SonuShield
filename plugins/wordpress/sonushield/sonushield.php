<?php
/**
 * Plugin Name: SonuShield Origin Signals
 * Plugin URI: https://github.com/sonudigitalmindset-design/SonuShield
 * Description: Forwards WordPress login failures to a SonuShield reverse proxy so its credential-stuffing detector can count them, and shows proxy reachability in wp-admin. No usernames or passwords are ever sent.
 * Version: 1.0.0
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Author: Sonu Digital Mindset
 * License: GPL-3.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain: sonushield
 *
 * SonuShield itself is a fork of 41Baloo/balooProxy (GPL-3.0).
 * This plugin is an optional origin-side companion: it only
 * talks to a proxy the site operator already runs.
 */

if (!defined('ABSPATH')) {
    exit;
}

define('SONUSHIELD_OPTION_GROUP', 'sonushield_options');
define('SONUSHIELD_OPTION_NAME', 'sonushield_settings');

/**
 * Default settings. The proxy base URL is the public URL of the
 * site as served through SonuShield; the secret is the
 * proxy.originSignals.secret value from the proxy's config.json.
 */
function sonushield_default_settings() {
    return array(
        'enabled'     => 0,
        'proxy_url'   => '',
        'secret'      => '',
        'domain'      => '',
        'status_check' => 1,
    );
}

function sonushield_get_settings() {
    $saved = get_option(SONUSHIELD_OPTION_NAME, array());
    if (!is_array($saved)) {
        $saved = array();
    }
    return array_merge(sonushield_default_settings(), $saved);
}

function sonushield_sanitize_settings($input) {
    $clean = sonushield_default_settings();
    if (!is_array($input)) {
        return $clean;
    }
    $clean['enabled'] = !empty($input['enabled']) ? 1 : 0;
    $clean['status_check'] = !empty($input['status_check']) ? 1 : 0;
    $clean['proxy_url'] = isset($input['proxy_url']) ? esc_url_raw(trim($input['proxy_url'])) : '';
    $clean['secret'] = isset($input['secret']) ? sanitize_text_field($input['secret']) : '';
    $clean['domain'] = isset($input['domain']) ? sanitize_text_field($input['domain']) : '';
    return $clean;
}

function sonushield_register_settings() {
    register_setting(
        SONUSHIELD_OPTION_GROUP,
        SONUSHIELD_OPTION_NAME,
        array(
            'type'              => 'array',
            'sanitize_callback' => 'sonushield_sanitize_settings',
            'default'           => sonushield_default_settings(),
        )
    );
    add_settings_section(
        'sonushield_main',
        __('Proxy connection', 'sonushield'),
        'sonushield_section_text',
        'sonushield'
    );
    add_settings_field(
        'sonushield_enabled',
        __('Enable signal forwarding', 'sonushield'),
        'sonushield_field_enabled',
        'sonushield',
        'sonushield_main'
    );
    add_settings_field(
        'sonushield_proxy_url',
        __('Proxy base URL', 'sonushield'),
        'sonushield_field_proxy_url',
        'sonushield',
        'sonushield_main'
    );
    add_settings_field(
        'sonushield_secret',
        __('Origin-signal secret', 'sonushield'),
        'sonushield_field_secret',
        'sonushield',
        'sonushield_main'
    );
    add_settings_field(
        'sonushield_domain',
        __('Domain name', 'sonushield'),
        'sonushield_field_domain',
        'sonushield',
        'sonushield_main'
    );
    add_settings_field(
        'sonushield_status_check',
        __('Show proxy status on the dashboard', 'sonushield'),
        'sonushield_field_status_check',
        'sonushield',
        'sonushield_main'
    );
}
add_action('admin_init', 'sonushield_register_settings');

function sonushield_section_text() {
    echo '<p>' . esc_html__('Enter the proxy details from your SonuShield config.json. The secret is stored in the WordPress options table; only administrators can view this page.', 'sonushield') . '</p>';
}

function sonushield_field_enabled() {
    $settings = sonushield_get_settings();
    echo '<label><input type="checkbox" name="' . esc_attr(SONUSHIELD_OPTION_NAME) . '[enabled]" value="1"' . checked(1, $settings['enabled'], false) . '> ' . esc_html__('Forward login failures to SonuShield', 'sonushield') . '</label>';
}

function sonushield_field_proxy_url() {
    $settings = sonushield_get_settings();
    echo '<input type="url" class="regular-text" name="' . esc_attr(SONUSHIELD_OPTION_NAME) . '[proxy_url]" value="' . esc_attr($settings['proxy_url']) . '" placeholder="https://example.com" spellcheck="false" autocomplete="off">';
    echo '<p class="description">' . esc_html__('The public URL served through the proxy, without a trailing slash.', 'sonushield') . '</p>';
}

function sonushield_field_secret() {
    $settings = sonushield_get_settings();
    echo '<input type="password" class="regular-text" name="' . esc_attr(SONUSHIELD_OPTION_NAME) . '[secret]" value="' . esc_attr($settings['secret']) . '" spellcheck="false" autocomplete="off">';
    echo '<p class="description">' . esc_html__('The proxy.originSignals.secret value from the proxy config.json. Sent only as the X-SonuShield-Signal header to the proxy URL above.', 'sonushield') . '</p>';
}

function sonushield_field_domain() {
    $settings = sonushield_get_settings();
    echo '<input type="text" class="regular-text" name="' . esc_attr(SONUSHIELD_OPTION_NAME) . '[domain]" value="' . esc_attr($settings['domain']) . '" placeholder="' . esc_attr(sonushield_default_domain()) . '" spellcheck="false" autocomplete="off">';
    echo '<p class="description">' . esc_html__('The domain name as configured in the proxy. Empty means the current site host.', 'sonushield') . '</p>';
}

function sonushield_field_status_check() {
    $settings = sonushield_get_settings();
    echo '<label><input type="checkbox" name="' . esc_attr(SONUSHIELD_OPTION_NAME) . '[status_check]" value="1"' . checked(1, $settings['status_check'], false) . '> ' . esc_html__('Show the SonuShield status widget on the dashboard', 'sonushield') . '</label>';
    echo '<p class="description">' . esc_html__('The widget calls the proxy health endpoint (/_bProxy/health), which the proxy only serves when its status page is enabled.', 'sonushield') . '</p>';
}

function sonushield_add_settings_page() {
    add_options_page(
        __('SonuShield', 'sonushield'),
        __('SonuShield', 'sonushield'),
        'manage_options',
        'sonushield',
        'sonushield_render_settings_page'
    );
}
add_action('admin_menu', 'sonushield_add_settings_page');

function sonushield_render_settings_page() {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have permission to access this page.', 'sonushield'));
    }
    echo '<div class="wrap"><h1>' . esc_html__('SonuShield', 'sonushield') . '</h1>';
    echo '<form method="post" action="options.php">';
    settings_fields(SONUSHIELD_OPTION_GROUP);
    do_settings_sections('sonushield');
    submit_button();
    echo '</form></div>';
}

function sonushield_default_domain() {
    $host = isset($_SERVER['HTTP_HOST']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'])) : '';
    return $host;
}

/**
 * The client IP as seen by the origin. SonuShield stamps the
 * real client IP on the x-real-ip header of the forwarded
 * request; that header is trusted only because the origin is
 * expected to be reachable solely through the proxy. When the
 * origin is also reachable directly, leave the header
 * untrusted by filtering sonushield_trust_proxy_ip to false.
 */
function sonushield_client_ip() {
    $trust_proxy = apply_filters('sonushield_trust_proxy_ip', true);
    if ($trust_proxy && !empty($_SERVER['HTTP_X_REAL_IP'])) {
        $ip = sanitize_text_field(wp_unslash($_SERVER['HTTP_X_REAL_IP']));
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
    }
    if (!empty($_SERVER['REMOTE_ADDR'])) {
        $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
    }
    return '';
}

/**
 * Forward one failed login to the proxy. The username is
 * deliberately NOT sent: the signal proves only that a login
 * failed from an IP on a path. Signals are throttled to one
 * per IP per 5 seconds so a failure burst cannot flood the
 * proxy.
 */
function sonushield_forward_login_failure($username) {
    $settings = sonushield_get_settings();
    if (empty($settings['enabled']) || $settings['proxy_url'] === '' || $settings['secret'] === '') {
        return;
    }
    $ip = sonushield_client_ip();
    if ($ip === '') {
        return;
    }
    $throttle_key = 'sonushield_signal_' . md5($ip);
    if (false !== get_transient($throttle_key)) {
        return;
    }
    set_transient($throttle_key, 1, 5);

    $domain = $settings['domain'] !== '' ? $settings['domain'] : sonushield_default_domain();
    $response = wp_remote_post(
        trailingslashit($settings['proxy_url']) . '_bProxy/origin-signal',
        array(
            'timeout' => 5,
            'headers' => array(
                'Content-Type'        => 'application/json',
                'X-SonuShield-Signal' => $settings['secret'],
            ),
            'body'    => wp_json_encode(array(
                'domain' => $domain,
                'type'   => 'login_failure',
                'ip'     => $ip,
                'path'   => '/wp-login.php',
            )),
        )
    );
    if (!is_wp_error($response)) {
        update_option('sonushield_last_signal', time(), false);
        update_option('sonushield_signal_count', (int) get_option('sonushield_signal_count', 0) + 1, false);
    }
}
add_action('wp_login_failed', 'sonushield_forward_login_failure');

/**
 * Dashboard widget: proxy reachability via the health
 * endpoint, plus the last forwarded signal. The health check
 * is cached for 60 seconds so the dashboard stays fast.
 */
function sonushield_add_dashboard_widget() {
    $settings = sonushield_get_settings();
    if (empty($settings['status_check'])) {
        return;
    }
    wp_add_dashboard_widget(
        'sonushield_status',
        __('SonuShield', 'sonushield'),
        'sonushield_render_dashboard_widget'
    );
}
add_action('wp_dashboard_setup', 'sonushield_add_dashboard_widget');

function sonushield_proxy_reachable() {
    $cached = get_transient('sonushield_health');
    if (false !== $cached) {
        return (bool) $cached;
    }
    $settings = sonushield_get_settings();
    $reachable = false;
    if ($settings['proxy_url'] !== '') {
        $response = wp_remote_get(
            trailingslashit($settings['proxy_url']) . '_bProxy/health',
            array('timeout' => 5)
        );
        if (!is_wp_error($response) && 200 === (int) wp_remote_retrieve_response_code($response)) {
            $reachable = true;
        }
    }
    set_transient('sonushield_health', $reachable ? 1 : 0, 60);
    return $reachable;
}

function sonushield_render_dashboard_widget() {
    $settings = sonushield_get_settings();
    if ($settings['proxy_url'] === '') {
        echo '<p>' . esc_html__('SonuShield is not configured yet.', 'sonushield') . ' <a href="' . esc_url(admin_url('options-general.php?page=sonushield')) . '">' . esc_html__('Open settings', 'sonushield') . '</a></p>';
        return;
    }
    if (sonushield_proxy_reachable()) {
        echo '<p>' . esc_html__('Proxy reachable (health endpoint answered).', 'sonushield') . '</p>';
    } else {
        echo '<p>' . esc_html__('Proxy unreachable, or the proxy health endpoint is disabled (proxy.statusPage).', 'sonushield') . '</p>';
    }
    $last = (int) get_option('sonushield_last_signal', 0);
    $count = (int) get_option('sonushield_signal_count', 0);
    if ($count > 0 && $last > 0) {
        echo '<p>' . esc_html(
            sprintf(
                /* translators: 1: number of signals, 2: date/time of the last signal */
                __('%1$d login-failure signals forwarded; last at %2$s.', 'sonushield'),
                $count,
                date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $last)
            )
        ) . '</p>';
    } else {
        echo '<p>' . esc_html__('No login-failure signals forwarded yet.', 'sonushield') . '</p>';
    }
    echo '<p><a href="' . esc_url(admin_url('options-general.php?page=sonushield')) . '">' . esc_html__('SonuShield settings', 'sonushield') . '</a></p>';
}

function sonushield_uninstall() {
    delete_option(SONUSHIELD_OPTION_NAME);
    delete_option('sonushield_last_signal');
    delete_option('sonushield_signal_count');
    delete_transient('sonushield_health');
}
register_uninstall_hook(__FILE__, 'sonushield_uninstall');
