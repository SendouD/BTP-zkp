use plotters::prelude::*;
use std::error::Error;
use std::fs::File;
use csv::ReaderBuilder;

fn main() -> Result<(), Box<dyn Error>> {
    let file = File::open("bench_results.csv")?;
    let mut rdr = ReaderBuilder::new().has_headers(false).from_reader(file);

    let mut data = Vec::new();
    for result in rdr.records() {
        let record = result?;
        let name = record[0].to_string();
        let time: u64 = record[1].parse()?;
        data.push((name, time));
    }

    // Drawing area
    let root = BitMapBackend::new("bench_results.png", (800, 600)).into_drawing_area();
    root.fill(&WHITE)?;

    let max_time = data.iter().map(|(_, t)| *t).max().unwrap_or(1);

    let mut chart = ChartBuilder::on(&root)
        .caption("ZKP Crates Performance", ("sans-serif", 30))
        .margin(20)
        .x_label_area_size(40)
        .y_label_area_size(50)
        .build_cartesian_2d(
            (0..data.len()).into_segmented(),
            0u64..(max_time + 50),
        )?;

    chart.configure_mesh().disable_mesh().x_labels(3).draw()?;

 // Draw labels above each bar
    chart.draw_series(
        data.iter().enumerate().map(|(i, (name, time))| {
            let x = SegmentValue::Exact(i);
            let y = *time + 5;
            Text::new(
                name.clone(),
                (x, y),
                ("sans-serif", 15).into_font().color(&BLACK),
            )
        }),
    )?;

    Ok(())
}
