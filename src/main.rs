#![allow(dead_code)]
extern crate webex;

use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client as http_client;
use oauth2::url::Url;
use oauth2::{
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

const CLIENT_ID: &str = env!("CLIENT_ID");
const CLIENT_SECRET: &str = env!("CLIENT_SECRET");

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io;
use tui::{
    backend::CrosstermBackend,
    text::Text,
    widgets::{Block, Borders, List, ListItem},
    Terminal,
};

async fn get_integration_token() -> Result<AccessToken, Box<dyn std::error::Error + Send + Sync>> {
    let client = BasicClient::new(
        ClientId::new(CLIENT_ID.to_string()),
        Some(ClientSecret::new(CLIENT_SECRET.to_string())),
        AuthUrl::new("http://webexapis.com/v1/authorize".to_string())?,
        Some(TokenUrl::new(
            "https://webexapis.com/v1/access_token".to_string(),
        )?),
    )
    .set_redirect_uri(
        RedirectUrl::new("http://localhost:8080".to_string()).expect("Invalid redirect url"),
    );

    let (auth_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        // This example is requesting access to the user's public repos and email.
        .add_scope(Scope::new("spark:all".to_string()))
        .url();

    println!("Browse to: {}", auth_url);

    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    if let Some(mut stream) = listener.incoming().flatten().next() {
        let code;
        let state;
        {
            let mut reader = BufReader::new(&stream);

            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();

            let redirect_url = request_line.split_whitespace().nth(1).unwrap();
            let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

            let code_pair = url
                .query_pairs()
                .find(|pair| {
                    let &(ref key, _) = pair;
                    key == "code"
                })
                .unwrap();

            let (_, value) = code_pair;
            code = AuthorizationCode::new(value.into_owned());

            let state_pair = url
                .query_pairs()
                .find(|pair| {
                    let &(ref key, _) = pair;
                    key == "state"
                })
                .unwrap();

            let (_, value) = state_pair;
            state = CsrfToken::new(value.into_owned());
        }

        let message = "Go back to your terminal :)";
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
            message.len(),
            message
        );
        stream.write_all(response.as_bytes()).unwrap();

        if state.secret() != csrf_state.secret() {
            return Err("returned state != csrf_state".into());
        }

        // Exchange the code with a token.
        let token_res = client.exchange_code(code).request_async(http_client).await;

        if let Ok(token) = token_res {
            return Ok(token.access_token().clone());
        }
    }
    Err("Error".into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let token = get_integration_token()
        .await
        .expect("Need token to continue");
    let token: &str = token.secret();
    let webex = webex::Webex::new(token).await;
    let mut rooms = webex.get_all_rooms().await.unwrap();
    rooms.sort_unstable_by(|r2, r1| r1.last_activity.cmp(&r2.last_activity));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    terminal.draw(|f| {
        let size = f.size();
        let items: Vec<ListItem> = rooms
            .iter()
            .map(|room| ListItem::new(Text::raw(room.title.clone())))
            .collect();
        let list = List::new(items).block(Block::default().title("Rooms").borders(Borders::ALL));
        f.render_widget(list, size);
    })?;

    std::thread::sleep(std::time::Duration::from_millis(5000));

    // restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}
