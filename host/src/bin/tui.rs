// Adapted from
// https://github.com/ratatui/ratatui/blob/9713828c838d567ec4d782869f1e2f267cc022b3/ratatui-widgets/examples/list.rs
// with the following licence

// The MIT License (MIT)

// Copyright (c) 2016-2022 Florian Dehau
// Copyright (c) 2023-2025 The Ratatui Developers

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! # [Ratatui] `List` example
//!
//! The latest version of this example is available in the [widget examples] folder in the
//! repository.
//!
//! Please note that the examples are designed to be run against the `main` branch of the Github
//! repository. This means that you may not be able to compile with the latest release version on
//! crates.io, or the one that you have installed locally.
//!
//! See the [examples readme] for more information on finding examples that match the version of the
//! library you are using.
//!
//! [Ratatui]: https://github.com/ratatui/ratatui
//! [widget examples]: https://github.com/ratatui/ratatui/blob/main/ratatui-widgets/examples
//! [examples readme]: https://github.com/ratatui/ratatui/blob/main/examples/README.md

use borsh::de::BorshDeserialize;
use borsh::BorshSerialize;
use color_eyre::Result;
use crossterm::event::{self, KeyCode, KeyEvent};
use host::{compute_fingerprint, prove_token_validation};
use jwt_core::PublicOutput;
use jwt_core::{CustomClaims, Issuer};
use methods::VERIFY_TOKEN_WITH_SOME_KEY_ID;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Flex, Layout, Margin, Offset, Rect};
use ratatui::style::{Color, Modifier, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Clear, List, ListState, Paragraph, Widget, Wrap};
use ratatui::{DefaultTerminal, Frame};
use risc0_zkvm::Receipt;
use std::fs::File;
use std::io::prelude::*;
use uuid::Uuid;

fn main() -> Result<()> {
    color_eyre::install()?;

    let sign_licence_form = InputForm {
        fields: Vec::from([
            StringField::new("Issuer ID", "National_Mining_Authority".to_owned()),
            StringField::new(
                "Path to issuer signing key file",
                "./test_data/national_mining_authority_sk.jwk".to_owned(),
            ),
            StringField::new("Subject ID", "ACME_Mining_Company".to_owned()),
            StringField::new(
                "Path to subject public key file",
                "./test_data/mining_company_pk.jwk".to_owned(),
            ),
            StringField::new("Valid from", "2025-01-01T00:00:00Z".to_owned()),
            StringField::new("Valid to", "2035-01-01T00:00:00Z".to_owned()),
            StringField::new("Country of operation", "GB".to_owned()),
            StringField::new("Region of operation", "Cornwall".to_owned()),
            StringField::new("Path to output licence file", "./licence.jwt".to_owned()),
        ]),
        focus: 0,
    };

    let sign_product_passport_form = InputForm {
        fields: Vec::from([
            StringField::new("Product", "Lithium".to_owned()),
            StringField::new("Issue date", "2025-12-01T00:00:00Z".to_owned()),
            StringField::new(
                "Path to signing key",
                "./test_data/mining_company_sk.jwk".to_owned(),
            ),
            StringField::new(
                "Path to output product passport file",
                "./product_passport.jwt".to_owned(),
            ),
        ]),
        focus: 0,
    };

    let prove_form = InputForm {
        fields: Vec::from([
            StringField::new(
                "Path to product passport",
                "./product_passport.jwt".to_owned(),
            ),
            StringField::new("Path to mining licence", "./licence.jwt".to_owned()),
            StringField::new(
                "Path to national mining authority verification key",
                "./test_data/national_mining_authority_pk.jwk".to_owned(),
            ),
            StringField::new(
                "Path to conflict zones file",
                "./test_data/conflict_zones.json".to_owned(),
            ),
            StringField::new("Path to output proof", "./receipt.bin".to_owned()),
        ]),
        focus: 0,
    };

    let verify_form = InputForm {
        fields: Vec::from([StringField::new(
            "Path to proof",
            "./receipt.bin".to_owned(),
        )]),
        focus: 0,
    };

    let app = App {
        state: AppState::Running,
        window: AppWindow::Home,
        home: SelectScreen::default(),
        sign_licence_form,
        sign_product_passport_form,
        prove_form,
        verify_form,
        result_text: "".to_string(),
        show_popup: false,
    };

    match ratatui::run(|terminal| app.run(terminal)) {
        Ok(()) => println!("Exited"),
        Err(err) => eprintln!("{err}"),
    }
    Ok(())
}

pub struct App {
    state: AppState,
    window: AppWindow,
    home: SelectScreen,
    sign_licence_form: InputForm,
    sign_product_passport_form: InputForm,
    prove_form: InputForm,
    verify_form: InputForm,
    result_text: String,
    show_popup: bool,
}

#[derive(PartialEq, Eq)]
enum AppState {
    Running,
    Cancelled,
    Submitted,
}

#[derive(PartialEq, Eq)]
enum AppWindow {
    Home,
    SignLicence,
    SignPP,
    Prove,
    Verify,
    Result,
}

impl App {
    pub fn run(mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        while self.state != AppState::Cancelled {
            while self.state != AppState::Submitted {
                terminal.draw(|frame: &mut Frame<'_>| self.render(frame))?;
                self.handle_events()?;
                if self.state == AppState::Cancelled {
                    return Ok(());
                }
            }
            // Now submitted
            match self.window {
                AppWindow::Home => (),
                AppWindow::SignLicence => {
                    let args = self.sign_licence_form.get_form_fields();

                    let mut claims = CustomClaims::new();

                    claims.add("issuer_id".to_string(), args[0].clone());
                    // 1 is signing key
                    claims.add("subject_id".to_string(), args[2].clone());
                    let mut f = std::fs::File::open(&args[3])
                        .expect(&format!("Could not find file {}", args[3]));
                    let mut subject_pk = String::new();
                    let _ = f
                        .read_to_string(&mut subject_pk)
                        .expect("Could not read from file");
                    claims.add("subject_pk".to_string(), subject_pk);
                    claims.add("issue_date".to_string(), args[4].clone());
                    claims.add("expiry_date".to_string(), args[5].clone());
                    claims.add("country_of_operation".to_string(), args[6].clone());
                    claims.add("region_of_operation".to_string(), args[7].clone());

                    let mut f = std::fs::File::open(&args[1])
                        .expect(&format!("Could not find file {}", args[1]));
                    let mut secret_key = String::new();
                    let _ = f
                        .read_to_string(&mut secret_key)
                        .expect("Could not read from file");

                    let iss = secret_key
                        .parse::<Issuer>()
                        .expect("failed to create issuer from secret key");

                    let token = iss
                        .generate_token(&claims)
                        .expect("failed to generate token");

                    let mut f = File::create(&args[8]).expect("Could not create JWT file");
                    f.write_all(&token.as_bytes())
                        .expect("Could not write to file");

                    self.window = AppWindow::Home;
                    self.state = AppState::Running;
                }

                AppWindow::SignPP => {
                    let args = self.sign_product_passport_form.get_form_fields();

                    let mut claims = CustomClaims::new();

                    claims.add("shipment_id".to_string(), Uuid::new_v4().to_string());
                    claims.add("product".to_string(), args[0].clone());
                    claims.add("issue_date".to_string(), args[1].clone());

                    let mut f = std::fs::File::open(&args[2])
                        .expect(&format!("Could not find file {}", args[2]));
                    let mut secret_key = String::new();
                    let _ = f
                        .read_to_string(&mut secret_key)
                        .expect("Could not read from file");

                    let iss = secret_key
                        .parse::<Issuer>()
                        .expect("failed to create issuer from secret key");
                    let token = iss
                        .generate_token(&claims)
                        .expect("failed to generate token");

                    let mut f = File::create(&args[3]).expect("Could not create JWT file");
                    f.write_all(&token.as_bytes())
                        .expect("Could not write to file");

                    self.window = AppWindow::Home;
                    self.state = AppState::Running;
                }
                AppWindow::Prove => {
                    let args = self.prove_form.get_form_fields();

                    let mut f = File::open(&args[0]).expect("Could not find passport file");
                    let mut passport = String::new();
                    f.read_to_string(&mut passport)
                        .expect("Could not parse passport from file");

                    let mut f = File::open(&args[1]).expect("Could not find licence file");
                    let mut licence = String::new();
                    f.read_to_string(&mut licence)
                        .expect("Could not parse licence from file");

                    let mut f = File::open(&args[2]).expect("Could not find public key file");
                    let mut pk = String::new();
                    f.read_to_string(&mut pk)
                        .expect("Could not parse public key from file");

                    let mut f = File::open(&args[3]).expect("Could not find conflict zones file");
                    let mut conflict_zones = String::new();
                    f.read_to_string(&mut conflict_zones)
                        .expect("Could not parse conflict zones from file");

                    let (receipt, _journal) =
                        prove_token_validation(passport, licence, pk, conflict_zones);

                    let mut f =
                        std::fs::File::create(&args[4]).expect("Could not create receipt file");
                    let mut serialized_receipt = Vec::new();
                    receipt
                        .serialize(&mut serialized_receipt)
                        .expect("Could not serialise the receipt");
                    f.write_all(&serialized_receipt)
                        .expect("Could not write receipt to file");

                    self.window = AppWindow::Home;
                    self.state = AppState::Running;
                }
                AppWindow::Verify => {
                    let args = self.verify_form.get_form_fields();

                    let mut f = File::open(&args[0]).expect("Could not find receipt file");
                    let mut receipt = Vec::new();
                    f.read_to_end(&mut receipt)
                        .expect("Could not parse token from file");

                    let receipt = Receipt::try_from_slice(&receipt)
                        .expect("Could not deserialise bytes as receipt");

                    let res = receipt.verify(VERIFY_TOKEN_WITH_SOME_KEY_ID);
                    if res.is_ok() {
                        self.result_text = String::from("Verification succeeded!");
                        self.result_text += format!("\nThe prover has proved they hold a product passport that is authenticated by a mining licence that is authenticated by the following national mining authority key:").as_str();
                        let public_outputs: PublicOutput = receipt
                            .journal
                            .decode()
                            .expect("Could not decode receipt journal");
                        let pk_digests: Vec<String> = public_outputs
                            .pks
                            .into_iter()
                            .map(|pk| compute_fingerprint(pk))
                            .collect();
                        self.result_text += format!("{:#?}", pk_digests).as_str();

                        self.result_text += format!(
                            "\nThe following information was proved about the product passport:"
                        )
                        .as_str();
                        self.result_text +=
                            format!("{:}", public_outputs.claims.pretty_print()).as_str();
                    }
                    self.show_popup = true;
                    self.window = AppWindow::Result;
                    self.state = AppState::Running;
                }
                AppWindow::Result => {
                    self.show_popup = false;
                    self.window = AppWindow::Home;
                    self.state = AppState::Running;
                }
            };
        }
        Ok(())
    }

    fn render(&mut self, frame: &mut Frame) {
        if self.show_popup {
            self.render_result(frame);
        } else {
            match self.window {
                AppWindow::Home => self.home.render(frame),
                AppWindow::SignLicence => self.sign_licence_form.render(frame),
                AppWindow::SignPP => self.sign_product_passport_form.render(frame),
                AppWindow::Prove => self.prove_form.render(frame),
                AppWindow::Verify => self.verify_form.render(frame),
                AppWindow::Result => self.render_result(frame),
            };
        }
    }

    fn handle_events(&mut self) -> Result<Vec<String>> {
        if let Some(key) = event::read()?.as_key_press_event() {
            match key.code {
                KeyCode::Esc => {
                    self.state = match self.window {
                        AppWindow::Home => AppState::Cancelled,
                        _ => {
                            self.window = AppWindow::Home;
                            self.show_popup = false;
                            AppState::Running
                        }
                    }
                }
                KeyCode::Enter => match self.window {
                    AppWindow::SignLicence
                    | AppWindow::SignPP
                    | AppWindow::Prove
                    | AppWindow::Verify
                    | AppWindow::Result => self.state = AppState::Submitted,
                    AppWindow::Home => match self.home.on_key_press(key) {
                        Some(result) => {
                            self.window = match result {
                                0 => AppWindow::SignLicence,
                                1 => AppWindow::SignPP,
                                2 => AppWindow::Prove,
                                3 => AppWindow::Verify,
                                _ => AppWindow::Home,
                            }
                        }
                        _ => (),
                    },
                },
                _ => match self.window {
                    AppWindow::SignLicence => self.sign_licence_form.on_key_press(key),
                    AppWindow::SignPP => self.sign_product_passport_form.on_key_press(key),
                    AppWindow::Prove => self.prove_form.on_key_press(key),
                    AppWindow::Verify => self.verify_form.on_key_press(key),
                    AppWindow::Home => {
                        if self.home.on_key_press(key) == Some(410) {
                            self.state = AppState::Cancelled;
                        };
                    }
                    _ => {
                        self.window = AppWindow::Home;
                        self.show_popup = false;
                        self.state = AppState::Running;
                    }
                },
            }
        }
        Ok(Vec::new())
    }

    fn render_result(&self, frame: &mut Frame) {
        let area = frame.area();

        let block = Block::bordered().title("Result").on_black();
        let area = percentage_area(area, 80, 80);
        frame.render_widget(Clear, area);
        frame.render_widget(block, area);

        let result = percentage_area(area, 90, 90);

        let binding = self.result_text.clone();
        let text: Text = binding.split('\n').collect();
        let paragraph = Paragraph::new(text.slow_blink()).wrap(Wrap { trim: true });
        frame.render_widget(paragraph, result);
    }
}

fn percentage_area(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let vertical = Layout::vertical([Constraint::Percentage(percent_y)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Percentage(percent_x)]).flex(Flex::Center);
    let [area] = vertical.areas(area);
    let [area] = horizontal.areas(area);
    area
}

struct SelectScreen {
    list_state: ListState,
}

impl Default for SelectScreen {
    fn default() -> Self {
        let mut list_state = ListState::default();
        list_state.select_first();
        SelectScreen { list_state }
    }
}

impl SelectScreen {
    /// Render the UI with various lists.
    fn render(&mut self, frame: &mut Frame) {
        let constraints = [
            Constraint::Length(1),
            Constraint::Fill(1),
            Constraint::Fill(1),
        ];
        let layout = Layout::vertical(constraints).spacing(1);
        let [top, first, _second] = frame.area().inner(Margin::new(2, 2)).layout(&layout);

        let title = Line::from_iter([
            Span::from("Zero-Knowledge Proof of Delivery").bold(),
            Span::from(" (Press 'q' to quit and arrow keys to navigate)"),
        ]);
        frame.render_widget(title.centered(), top);

        self.render_list(frame, first);
    }

    pub fn render_list(&mut self, frame: &mut Frame, area: Rect) {
        let items = [
            "Sign a new mining licence",
            "Sign a product passport",
            "Generate a Zero-Knowledge Product Passport",
            "Verify a Zero-Knowledge Product Passport",
        ];
        let list = List::new(items)
            .style(Color::White)
            .highlight_style(Modifier::REVERSED)
            .highlight_symbol("> ");

        frame.render_stateful_widget(list, area, &mut self.list_state);
    }

    fn on_key_press(&mut self, event: KeyEvent) -> Option<usize> {
        match event.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.list_state.select_next();
                None
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.list_state.select_previous();
                None
            }
            KeyCode::Char('q') | KeyCode::Esc => Some(410),
            KeyCode::Enter => self.list_state.selected(),
            _ => None,
        }
    }
}

struct InputForm {
    focus: usize,
    fields: Vec<StringField>,
}

impl InputForm {
    // Handle focus navigation or pass the event to the focused field.
    fn on_key_press(&mut self, event: KeyEvent) {
        match event.code {
            KeyCode::Tab | KeyCode::Down => {
                if self.focus < self.fields.len() - 1 {
                    self.focus += 1;
                }
            }
            KeyCode::BackTab | KeyCode::Up => {
                if self.focus > 0 {
                    self.focus -= 1;
                }
            }
            _ => self.fields[self.focus].on_key_press(event),
        }
    }

    fn render(&self, frame: &mut Frame) {
        let area = frame.area();

        let block = Block::bordered().title("Press <Enter> to submit").on_blue();
        let area = percentage_area(area, 80, 80);
        frame.render_widget(Clear, area);
        frame.render_widget(block, area);

        let layout = Layout::vertical(Constraint::from_lengths(vec![1; self.fields.len()]));
        let areas = area.inner(Margin::new(2, 2)).layout_vec(&layout);
        for index in 0..self.fields.len() {
            frame.render_widget(&self.fields[index], areas[index]);
        }

        let cursor_position = areas[self.focus] + self.fields[self.focus].cursor_offset();

        frame.set_cursor_position(cursor_position);
    }

    pub fn get_form_fields(&self) -> Vec<String> {
        self.fields.iter().map(|e| e.value.clone()).collect()
    }
}

#[derive(Debug)]
struct StringField {
    label: &'static str,
    value: String,
}

impl StringField {
    const fn new(label: &'static str, value: String) -> Self {
        Self { label, value }
    }

    fn on_key_press(&mut self, event: KeyEvent) {
        match event.code {
            KeyCode::Char(c) => self.value.push(c),
            KeyCode::Backspace => {
                self.value.pop();
            }
            _ => {}
        }
    }

    const fn cursor_offset(&self) -> Offset {
        let x = (self.label.len() + self.value.len() + 2) as i32;
        Offset::new(x, 0)
    }
}

impl Widget for &StringField {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let layout = Layout::horizontal([
            Constraint::Length(self.label.len() as u16 + 2),
            Constraint::Fill(1),
        ]);
        let [label_area, value_area] = area.layout(&layout);
        let label = Line::from_iter([self.label, ": "]).bold();
        label.render(label_area, buf);
        self.value.clone().render(value_area, buf);
    }
}
