use crate::DbConnLike;

/// List all enabled regions
pub async fn list_enabled_regions(conn: impl DbConnLike<'_>) -> Result<Vec<String>, sqlx::Error> {
    Ok(sqlx::query!(
        r#"
            SELECT name
            FROM enabled_regions
        "#
    )
    .fetch_all(conn)
    .await?
    .into_iter()
    .map(|v| v.name)
    .collect())
}

pub async fn enable_region(conn: impl DbConnLike<'_>, region: String) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
            INSERT INTO enabled_regions (name) VALUES ($1)
        "#,
        region
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn disable_region(conn: impl DbConnLike<'_>, region: String) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
            DELETE FROM enabled_regions WHERE name = $1
        "#,
        region,
    )
    .execute(conn)
    .await?;
    Ok(())
}
