use chrono::{DateTime, Datelike};
use plotters::prelude::*;

use crate::routes::DisplayLogRow;

pub fn render_graph(
    buffer: &mut String,
    logs: &[DisplayLogRow],
) -> Result<(), Box<dyn core::error::Error>> {
    let root_drawing_area = SVGBackend::with_string(buffer, (830, 500)).into_drawing_area();

    root_drawing_area.fill(&WHITE).unwrap();

    // X-axis bounds
    let from = logs
        .iter()
        .map(|l| l.time.timestamp())
        .min()
        .unwrap_or_default();
    let to = logs
        .iter()
        .map(|l| l.time.timestamp())
        .max()
        .unwrap_or_default();

    let mut chart = ChartBuilder::on(&root_drawing_area)
        .set_label_area_size(LabelAreaPosition::Left, 40)
        .set_label_area_size(LabelAreaPosition::Bottom, 40)
        .build_cartesian_2d(from..to, -100.0..25.0)
        .unwrap();

    chart
        .configure_mesh()
        .x_label_formatter(&|vt| {
            let y = DateTime::from_timestamp(*vt, 0).unwrap().year();
            let m = DateTime::from_timestamp(*vt, 0).unwrap().month();
            let d = DateTime::from_timestamp(*vt, 0).unwrap().day();
            let t = DateTime::from_timestamp(*vt, 0).unwrap().time();
            format!("{y}-{m}-{d} {t}")
        })
        .draw()
        .unwrap();

    chart
        .draw_series(
            // We don't care about the color given here, we'll set it in CSS anyway
            logs.iter()
                .map(|log| Circle::new((log.time.timestamp(), log.score), 3, BLACK.filled())),
        )
        .unwrap();

    Ok(())
}
