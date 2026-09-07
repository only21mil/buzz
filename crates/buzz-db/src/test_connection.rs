//! Connection changes for private PostgreSQL test fixtures.

use sqlx::postgres::PgConnectOptions;
use url::Url;

pub(crate) fn database_url(base: &str, database: &str) -> String {
    let mut url = Url::parse(base).expect("parse test database URL");
    url.set_path(database);
    // SQLx gives a query-string dbname precedence over the path.
    if url.query_pairs().any(|(key, _)| key == "dbname") {
        let pairs: Vec<_> = url
            .query_pairs()
            .filter(|(key, _)| key != "dbname")
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        url.query_pairs_mut().clear().extend_pairs(pairs);
    }
    url.into()
}

pub(crate) fn role_options(base: &str, role: &str, password: &str) -> PgConnectOptions {
    base.parse::<PgConnectOptions>()
        .expect("parse test role connection")
        .username(role)
        .password(password)
}

#[test]
fn database_changes_preserve_socket_and_connection_options() {
    for scheme in ["postgres", "postgresql"] {
        for db_override in ["", "&dbname=old_override"] {
            let base = format!(
                "{scheme}://buzz_test@buzz-test.invalid/original?host=%2Ftask%2Fpg%2Fs&application_name=fixture&sslmode=disable&options=-c%20statement_timeout%3D1000{db_override}"
            );
            let changed = database_url(&base, "scratch");
            let options: PgConnectOptions = changed.parse().expect("SQLx accepts changed URL");
            assert_eq!(options.get_database(), Some("scratch"));
            assert_eq!(
                options.get_socket().expect("socket retained").to_str(),
                Some("/task/pg/s")
            );
            assert_eq!(options.get_username(), "buzz_test");
            assert_eq!(options.get_application_name(), Some("fixture"));
            assert_eq!(options.get_options(), Some("-c statement_timeout=1000"));
            assert!(matches!(
                options.get_ssl_mode(),
                sqlx::postgres::PgSslMode::Disable
            ));
            assert_eq!(
                Url::parse(&changed).expect("parse").host_str(),
                Some("buzz-test.invalid")
            );
        }
    }
}

#[test]
fn database_changes_preserve_tcp_authority_and_query_bytes() {
    let base =
        "postgres://fixture:p%40ss@db.invalid:6543/original?application_name=a%2Fb&sslmode=require";
    let changed = database_url(base, "scratch");
    assert_eq!(
        changed,
        "postgres://fixture:p%40ss@db.invalid:6543/scratch?application_name=a%2Fb&sslmode=require"
    );
}

#[test]
fn role_changes_preserve_socket_database_and_options_for_both_schemes() {
    for scheme in ["postgres", "postgresql"] {
        let base = format!(
            "{scheme}://buzz_test@buzz-test.invalid/original?host=%2Ftask%2Fpg%2Fs&user=old_role&password=old_fixture_password&application_name=fixture&options=-c%20statement_timeout%3D1000"
        );
        let options = role_options(&base, "probe_role", "fixture_password");
        assert_eq!(options.get_username(), "probe_role");
        assert_eq!(options.get_database(), Some("original"));
        assert_eq!(
            options.get_socket().expect("socket retained").to_str(),
            Some("/task/pg/s")
        );
        assert_eq!(options.get_application_name(), Some("fixture"));
        assert_eq!(options.get_options(), Some("-c statement_timeout=1000"));
    }
}
