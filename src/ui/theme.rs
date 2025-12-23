//! Theme system for NoirCast TUI
//!
//! Provides multiple color schemes with consistent styling

use ratatui::style::Color;
use serde::{Deserialize, Serialize};

/// Available themes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ThemeType {
    #[default]
    Noir,       // Original black + neon green
    Matrix,     // Green on black terminal style
    Cyberpunk,  // Purple/pink neon
    Ocean,      // Blue tones
    Sunset,     // Orange/red warm tones
    Frost,      // Light blue/white cool tones
    Hacker,     // Amber on black (old school)
    Dracula,    // Popular dark theme
}

impl ThemeType {
    pub fn all() -> Vec<ThemeType> {
        vec![
            ThemeType::Noir,
            ThemeType::Matrix,
            ThemeType::Cyberpunk,
            ThemeType::Ocean,
            ThemeType::Sunset,
            ThemeType::Frost,
            ThemeType::Hacker,
            ThemeType::Dracula,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            ThemeType::Noir => "Noir",
            ThemeType::Matrix => "Matrix",
            ThemeType::Cyberpunk => "Cyberpunk",
            ThemeType::Ocean => "Ocean",
            ThemeType::Sunset => "Sunset",
            ThemeType::Frost => "Frost",
            ThemeType::Hacker => "Hacker",
            ThemeType::Dracula => "Dracula",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            ThemeType::Noir => "Black + neon green (default)",
            ThemeType::Matrix => "Green terminal aesthetic",
            ThemeType::Cyberpunk => "Purple/pink neon vibes",
            ThemeType::Ocean => "Deep blue tones",
            ThemeType::Sunset => "Warm orange/red palette",
            ThemeType::Frost => "Cool blue/white ice",
            ThemeType::Hacker => "Amber on black (retro)",
            ThemeType::Dracula => "Popular dark theme",
        }
    }

    pub fn colors(&self) -> ThemeColors {
        match self {
            ThemeType::Noir => ThemeColors {
                bg: Color::Rgb(0, 0, 0),
                fg_primary: Color::White,
                fg_secondary: Color::Rgb(128, 128, 128),
                fg_dim: Color::Rgb(80, 80, 80),
                fg_hint: Color::Rgb(120, 120, 120),
                accent: Color::Rgb(80, 200, 100),
                accent_bright: Color::Rgb(100, 255, 120),
                border_active: Color::Rgb(80, 200, 100),
                border_inactive: Color::Rgb(40, 40, 40),
                success: Color::Rgb(80, 200, 100),
                warning: Color::Rgb(200, 180, 80),
                error: Color::Rgb(200, 80, 80),
                info: Color::Rgb(100, 150, 200),
            },
            ThemeType::Matrix => ThemeColors {
                bg: Color::Rgb(0, 10, 0),
                fg_primary: Color::Rgb(0, 255, 65),
                fg_secondary: Color::Rgb(0, 180, 45),
                fg_dim: Color::Rgb(0, 100, 25),
                fg_hint: Color::Rgb(0, 140, 35),
                accent: Color::Rgb(0, 255, 65),
                accent_bright: Color::Rgb(150, 255, 150),
                border_active: Color::Rgb(0, 255, 65),
                border_inactive: Color::Rgb(0, 60, 15),
                success: Color::Rgb(0, 255, 100),
                warning: Color::Rgb(200, 255, 0),
                error: Color::Rgb(255, 50, 50),
                info: Color::Rgb(0, 200, 200),
            },
            ThemeType::Cyberpunk => ThemeColors {
                bg: Color::Rgb(15, 0, 20),
                fg_primary: Color::Rgb(255, 255, 255),
                fg_secondary: Color::Rgb(180, 100, 200),
                fg_dim: Color::Rgb(100, 50, 120),
                fg_hint: Color::Rgb(140, 80, 160),
                accent: Color::Rgb(255, 0, 200),
                accent_bright: Color::Rgb(255, 100, 255),
                border_active: Color::Rgb(255, 0, 200),
                border_inactive: Color::Rgb(60, 20, 70),
                success: Color::Rgb(0, 255, 200),
                warning: Color::Rgb(255, 200, 0),
                error: Color::Rgb(255, 50, 100),
                info: Color::Rgb(100, 200, 255),
            },
            ThemeType::Ocean => ThemeColors {
                bg: Color::Rgb(10, 20, 30),
                fg_primary: Color::Rgb(200, 220, 255),
                fg_secondary: Color::Rgb(100, 140, 180),
                fg_dim: Color::Rgb(50, 80, 110),
                fg_hint: Color::Rgb(80, 120, 160),
                accent: Color::Rgb(0, 180, 255),
                accent_bright: Color::Rgb(100, 220, 255),
                border_active: Color::Rgb(0, 180, 255),
                border_inactive: Color::Rgb(30, 50, 70),
                success: Color::Rgb(0, 200, 150),
                warning: Color::Rgb(255, 200, 100),
                error: Color::Rgb(255, 100, 100),
                info: Color::Rgb(100, 180, 255),
            },
            ThemeType::Sunset => ThemeColors {
                bg: Color::Rgb(25, 15, 15),
                fg_primary: Color::Rgb(255, 240, 220),
                fg_secondary: Color::Rgb(200, 150, 120),
                fg_dim: Color::Rgb(120, 80, 60),
                fg_hint: Color::Rgb(160, 120, 90),
                accent: Color::Rgb(255, 120, 50),
                accent_bright: Color::Rgb(255, 180, 100),
                border_active: Color::Rgb(255, 120, 50),
                border_inactive: Color::Rgb(60, 40, 30),
                success: Color::Rgb(150, 220, 100),
                warning: Color::Rgb(255, 200, 50),
                error: Color::Rgb(255, 80, 80),
                info: Color::Rgb(255, 180, 120),
            },
            ThemeType::Frost => ThemeColors {
                bg: Color::Rgb(15, 25, 35),
                fg_primary: Color::Rgb(220, 240, 255),
                fg_secondary: Color::Rgb(150, 180, 200),
                fg_dim: Color::Rgb(80, 110, 140),
                fg_hint: Color::Rgb(120, 150, 180),
                accent: Color::Rgb(150, 220, 255),
                accent_bright: Color::Rgb(200, 240, 255),
                border_active: Color::Rgb(150, 220, 255),
                border_inactive: Color::Rgb(40, 60, 80),
                success: Color::Rgb(100, 220, 180),
                warning: Color::Rgb(255, 220, 150),
                error: Color::Rgb(255, 120, 120),
                info: Color::Rgb(150, 200, 255),
            },
            ThemeType::Hacker => ThemeColors {
                bg: Color::Rgb(0, 0, 0),
                fg_primary: Color::Rgb(255, 180, 0),
                fg_secondary: Color::Rgb(180, 130, 0),
                fg_dim: Color::Rgb(100, 70, 0),
                fg_hint: Color::Rgb(140, 100, 0),
                accent: Color::Rgb(255, 180, 0),
                accent_bright: Color::Rgb(255, 220, 100),
                border_active: Color::Rgb(255, 180, 0),
                border_inactive: Color::Rgb(50, 35, 0),
                success: Color::Rgb(180, 255, 0),
                warning: Color::Rgb(255, 255, 0),
                error: Color::Rgb(255, 80, 0),
                info: Color::Rgb(255, 200, 100),
            },
            ThemeType::Dracula => ThemeColors {
                bg: Color::Rgb(0, 0, 0),
                fg_primary: Color::Rgb(248, 248, 242),
                fg_secondary: Color::Rgb(70, 80, 110),
                fg_dim: Color::Rgb(50, 52, 68),
                fg_hint: Color::Rgb(70, 80, 110),
                accent: Color::Rgb(189, 147, 249),
                accent_bright: Color::Rgb(255, 121, 198),
                border_active: Color::Rgb(189, 147, 249),
                border_inactive: Color::Rgb(50, 52, 68),
                success: Color::Rgb(80, 250, 123),
                warning: Color::Rgb(255, 184, 108),
                error: Color::Rgb(255, 85, 85),
                info: Color::Rgb(139, 233, 253),
            },
        }
    }

}

/// Color values for a theme
#[derive(Debug, Clone, Copy)]
pub struct ThemeColors {
    pub bg: Color,
    pub fg_primary: Color,
    pub fg_secondary: Color,
    pub fg_dim: Color,
    pub fg_hint: Color,
    pub accent: Color,
    pub accent_bright: Color,
    pub border_active: Color,
    pub border_inactive: Color,
    pub success: Color,
    pub warning: Color,
    pub error: Color,
    pub info: Color,
}

impl Default for ThemeColors {
    fn default() -> Self {
        ThemeType::Noir.colors()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_themes_have_colors() {
        for theme in ThemeType::all() {
            let _colors = theme.colors();
        }
    }

}
