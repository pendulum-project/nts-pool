use chrono::DateTime;
use plotters::prelude::*;

use nts_pool_shared::IpVersion;

use crate::models::time_source::LogRow;

pub fn render_graph(
    buffer: &mut String,
    logs: &[LogRow],
) -> Result<(), Box<dyn core::error::Error>> {
    let root_drawing_area = SVGBackend::with_string(buffer, (830, 500)).into_drawing_area();

    root_drawing_area.fill(&WHITE).unwrap();

    // X-axis bounds
    let from = logs
        .iter()
        .map(|l| l.received_at.timestamp())
        .min()
        .unwrap_or_default();
    let to = logs
        .iter()
        .map(|l| l.received_at.timestamp())
        .max()
        .unwrap_or_default();

    let mut chart = ChartBuilder::on(&root_drawing_area)
        .set_label_area_size(LabelAreaPosition::Left, 40)
        .set_label_area_size(LabelAreaPosition::Bottom, 40)
        .build_cartesian_2d(from..to, -100.0..25.0)
        .unwrap();

    chart
        .configure_mesh()
        .x_label_formatter(&|vt| format!("{}", DateTime::from_timestamp(*vt, 0).unwrap().time()))
        .draw()
        .unwrap();

    // Color names align with colors as defined in CSS
    const ORANGE_DELIGHT: RGBColor = RGBColor(253, 193, 83);
    const ELECTRIC_LEMONADE: RGBColor = RGBColor(83, 228, 253);
    const BLISTERING_MARS: RGBColor = RGBColor(253, 108, 83);
    const GREEN_OOZE: RGBColor = RGBColor(142, 253, 83);

    // Convenience alias to keep shapes of graph point and legend in sync
    type Shape<C, S> = Circle<C, S>;

    for (color, protocol) in [
        (ORANGE_DELIGHT, IpVersion::Ipv4),
        (ELECTRIC_LEMONADE, IpVersion::Ipv6),
        (BLISTERING_MARS, IpVersion::Srvv4),
        (GREEN_OOZE, IpVersion::Srvv6),
    ]
    .iter()
    {
        chart
            .draw_series(logs.iter().filter_map(|log| {
                if log.protocol == *protocol {
                    Some(Shape::new(
                        (log.received_at.timestamp(), log.score),
                        3,
                        color.filled(),
                    ))
                } else {
                    None
                }
            }))?
            .label(protocol.to_string())
            .legend(|(x, y)| Shape::new((x + 12, y - 1), 4, color.filled()));
    }

    chart
        .configure_series_labels()
        .label_font(("Roboto", 20))
        .border_style(BLACK)
        .background_style(WHITE)
        .draw()?;

    Ok(())
}
