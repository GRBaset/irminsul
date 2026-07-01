use std::fs::File;
use std::path::Path;
use std::process::Command;
use std::{env, io};

use flate2::Compression;
use flate2::write::GzEncoder;
use winresource::WindowsResource;

#[tokio::main]
async fn main() -> io::Result<()> {
    // Download new game data and save it in a location to be included by the source.
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let cache_path = Path::new(&out_dir).join("game_data.json");

    let mut db = anime_game_data::AnimeGameData::new_with_cache(&cache_path);
    if db.needs_update().await.unwrap() {
        db.update().await.unwrap();
        let out_path = Path::new(&out_dir).join("game_data.gz");
        let f = File::create(out_path).unwrap();
        let writer = GzEncoder::new(f, Compression::best());
        db.save_to_writer(writer).unwrap();
    }

    // Add icon to windows binary.
    if env::var_os("CARGO_CFG_WINDOWS").is_some() {
        WindowsResource::new()
            .set_icon("assets/icon.ico")
            .set_manifest(
                r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
        <requestedPrivileges>
            <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
        </requestedPrivileges>
    </security>
</trustInfo>
</assembly>
"#,
            )
            .compile()?;
    }

    #[cfg(all(unix, feature = "static-libpcap"))]
    {
        println!("cargo:rustc-link-lib=static=pcap");
    }

    // Set version with git hash for pre-releases
    let version = env!("CARGO_PKG_VERSION");
    let is_release = env::var("RELEASE_BUILD").is_ok();
    let is_debug = env::var("PROFILE").map(|p| p == "debug").unwrap_or(false);

    let full_version = if is_release {
        version.to_string()
    } else {
        // Get git hash at build.rs runtime
        let git_hash = Command::new("git")
            .args(["rev-parse", "--short=7", "HEAD"])
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    String::from_utf8(output.stdout).ok()
                } else {
                    None
                }
            })
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        if is_debug {
            format!("{}-debug.{}", version, git_hash)
        } else {
            format!("{}-pre.{}", version, git_hash)
        }
    };

    println!("cargo:rustc-env=APP_VERSION={}", full_version);
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-env-changed=RELEASE_BUILD");

    // Extract GitHub repository info from git remote
    let repo_info = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .and_then(|url| {
            let url = url.trim();
            // Handle both HTTPS and SSH URLs
            // HTTPS: https://github.com/owner/repo.git
            // SSH: git@github.com:owner/repo.git
            url.strip_prefix("https://github.com/")
                .or_else(|| url.strip_prefix("git@github.com:"))
                .map(|rest| rest.trim_end_matches(".git").to_string())
        });

    if let Some(repo) = repo_info {
        let parts: Vec<&str> = repo.split('/').collect();
        if parts.len() == 2 {
            println!("cargo:rustc-env=GITHUB_REPO_OWNER={}", parts[0]);
            println!("cargo:rustc-env=GITHUB_REPO_NAME={}", parts[1]);
        }
    }

    Ok(())
}
