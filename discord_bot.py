import discord
from discord.ext import commands
import os
from dotenv import load_dotenv
from linkgetter import (
    normalize_url, is_valid_url, check_suspicious_pattern,
    check_brand_impersonation, expand_shortened_url,
    check_virustotal, check_google_safe_browsing,
    ai_predict_maliciousness, calculate_rule_based_score,
    get_verdict
)
from database import create_database
from scan_history import create_scan_history_table, save_scan_result

# Load environment variables
load_dotenv()
create_database()
create_scan_history_table()

# Bot setup - Disable default help command
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)


@bot.event
async def on_ready():
    print(f'✅ {bot.user} is now online!')
    print(f'📊 Connected to {len(bot.guilds)} servers')
    print('🛡️ URL Security Bot is ready to protect!')


@bot.command(name='scan')
async def scan_url(ctx, url: str = None):
    """Scan a URL for threats"""

    if not url:
        embed = discord.Embed(
            title="❌ Missing URL",
            description="Please provide a URL to scan!\n\n**Usage:** `!scan <url>`\n**Example:** `!scan https://google.com`",
            color=discord.Color.red()
        )
        await ctx.send(embed=embed)
        return

    # Send initial message
    embed = discord.Embed(
        title="🔍 Scanning URL...",
        description=f"Analyzing: `{url}`\n\nPlease wait...",
        color=discord.Color.blue()
    )
    embed.set_footer(text="This may take 5-10 seconds")
    msg = await ctx.send(embed=embed)

    try:
        # Normalize URL
        url = normalize_url(url)

        # Validate URL
        if not is_valid_url(url):
            embed = discord.Embed(
                title="❌ Invalid URL",
                description="The provided URL is not valid!\n\nPlease check the URL format and try again.",
                color=discord.Color.red()
            )
            await msg.edit(embed=embed)
            return

        # Expand shortened URLs
        expansion_result = expand_shortened_url(url)
        url_to_check = expansion_result.get('expanded_url', url)

        if expansion_result.get('is_shortened'):
            embed = discord.Embed(
                title="🔗 Shortened URL Detected",
                description=f"**Original:** `{expansion_result['original_url']}`\n**Expanded:** `{url_to_check}`",
                color=discord.Color.orange()
            )
            await ctx.send(embed=embed)

        # Check suspicious patterns
        has_suspicious = check_suspicious_pattern(url_to_check)

        # Check brand impersonation
        impersonation_result = check_brand_impersonation(url_to_check)

        # Check VirusTotal
        vt_result = check_virustotal(url_to_check)

        # Check Google Safe Browsing
        gs_result = check_google_safe_browsing(url_to_check)

        # Compile scan data
        scan_data = {
            'url': url_to_check,
            'real_domain': impersonation_result.get('real_domain', ''),
            'has_suspicious_keywords': has_suspicious,
            'is_impersonation': impersonation_result.get('impersonation', False),
            'vt_malicious': vt_result.get('malicious', 0) if 'error' not in vt_result else 0,
            'vt_suspicious': vt_result.get('suspicious', 0) if 'error' not in vt_result else 0,
            'gsb_threat': gs_result.get('threat_detected', False) if 'error' not in gs_result else False,
            'is_shortened': expansion_result.get('is_shortened', False),
            'suspicious_keywords': 'Found' if has_suspicious else 'None',
            'impersonation': impersonation_result.get('impersonation', False)
        }

        # Get AI prediction
        ai_result = ai_predict_maliciousness(url_to_check, scan_data)

        # Save to database
        scan_data['verdict'] = ai_result['verdict']
        save_scan_result(url_to_check, scan_data)

        # Create result embed
        score = ai_result['score']
        verdict = ai_result['verdict']

        # Set color based on verdict
        if verdict == "SAFE":
            color = discord.Color.green()
            emoji = "✅"
        elif verdict == "SUSPICIOUS":
            color = discord.Color.orange()
            emoji = "⚠️"
        elif verdict == "DANGEROUS":
            color = discord.Color.red()
            emoji = "🚨"
        else:  # CRITICAL
            color = discord.Color.dark_red()
            emoji = "☠️"

        embed = discord.Embed(
            title=f"{emoji} Scan Results - {verdict}",
            description=f"**URL:** `{url_to_check}`",
            color=color
        )

        # Add fields
        embed.add_field(
            name="🎯 Risk Score",
            value=f"**{score}/100**",
            inline=True
        )

        embed.add_field(
            name="📊 Confidence",
            value=ai_result.get('confidence', 'MEDIUM'),
            inline=True
        )

        embed.add_field(
            name="🌐 Real Domain",
            value=f"`{impersonation_result.get('real_domain', 'Unknown')}`",
            inline=True
        )

        # VirusTotal results
        if 'error' not in vt_result:
            vt_text = f"🚨 Malicious: **{vt_result['malicious']}**\n⚠️ Suspicious: **{vt_result['suspicious']}**\n✅ Harmless: **{vt_result['harmless']}**"
            embed.add_field(name="🛡️ VirusTotal Scan", value=vt_text, inline=False)
        else:
            embed.add_field(name="🛡️ VirusTotal Scan", value=f"❌ {vt_result['error']}", inline=False)

        # Google Safe Browsing
        if 'error' not in gs_result:
            if gs_result['threat_detected']:
                gsb_text = "🚨 **THREAT DETECTED**"
                if gs_result.get('threats'):
                    gsb_text += f"\n**Types:** {', '.join(gs_result['threats'])}"
            else:
                gsb_text = "✅ **No threats detected**"
            embed.add_field(name="🔐 Google Safe Browsing", value=gsb_text, inline=False)
        else:
            embed.add_field(name="🔐 Google Safe Browsing", value=f"❌ {gs_result['error']}", inline=False)

        # Brand Impersonation
        if impersonation_result.get('impersonation'):
            embed.add_field(
                name="⚠️ Brand Impersonation Detected",
                value=f"**Impersonating:** {', '.join(impersonation_result['brands'])}",
                inline=False
            )

        # AI Explanation
        embed.add_field(
            name="🤖 AI Analysis",
            value=ai_result.get('explanation', 'No explanation available'),
            inline=False
        )

        embed.set_footer(text="CyberSecurity Bot | Stay Safe Online 🛡️")
        embed.timestamp = discord.utils.utcnow()

        await msg.edit(embed=embed)

    except Exception as e:
        embed = discord.Embed(
            title="❌ Error Occurred",
            description=f"An error occurred while scanning the URL:\n\n```{str(e)}```",
            color=discord.Color.red()
        )
        embed.set_footer(text="Please try again or contact support")
        await msg.edit(embed=embed)
        print(f"Error in scan command: {e}")


@bot.command(name='help')
async def help_command(ctx):
    """Show help message"""
    embed = discord.Embed(
        title="🛡️ URL Security Bot - Help",
        description="Protect yourself from malicious URLs with AI-powered threat detection!",
        color=discord.Color.blue()
    )

    embed.add_field(
        name="📝 Commands",
        value=(
            "**`!scan <url>`**\n"
            "Scan a URL for threats and malicious content\n"
            "Example: `!scan https://google.com`\n\n"
            "**`!help`**\n"
            "Show this help message\n\n"
            "**`!about`**\n"
            "Learn more about this bot"
        ),
        inline=False
    )

    embed.add_field(
        name="✨ Features",
        value=(
            "• **Multi-API Threat Detection** (VirusTotal, Google Safe Browsing)\n"
            "• **AI-Powered Risk Analysis** (Google Gemini)\n"
            "• **Brand Impersonation Detection**\n"
            "• **URL Shortener Expansion**\n"
            "• **Real-time Threat Scoring**"
        ),
        inline=False
    )

    embed.add_field(
        name="🎯 Risk Levels",
        value=(
            "✅ **SAFE (0-20)** - No threats detected\n"
            "⚠️ **SUSPICIOUS (21-50)** - Some red flags\n"
            "🚨 **DANGEROUS (51-80)** - High risk detected\n"
            "☠️ **CRITICAL (81-100)** - Severe threat!"
        ),
        inline=False
    )

    embed.set_footer(text="Made with ❤️ | Stay safe online!")
    embed.timestamp = discord.utils.utcnow()

    await ctx.send(embed=embed)


@bot.command(name='about')
async def about_command(ctx):
    """Show information about the bot"""
    embed = discord.Embed(
        title="🛡️ About URL Security Bot",
        description="An advanced cybersecurity tool that protects you from malicious URLs using AI and multiple threat intelligence APIs.",
        color=discord.Color.purple()
    )

    embed.add_field(
        name="🔬 Technology Stack",
        value=(
            "• **Python** - Core programming language\n"
            "• **Discord.py** - Bot framework\n"
            "• **VirusTotal API** - Malware detection\n"
            "• **Google Safe Browsing** - Phishing protection\n"
            "• **Google Gemini AI** - Intelligent analysis\n"
            "• **SQLite** - Database storage"
        ),
        inline=False
    )

    embed.add_field(
        name="📊 Statistics",
        value=(
            f"• Servers: **{len(bot.guilds)}**\n"
            f"• Latency: **{round(bot.latency * 1000)}ms**\n"
            "• Database: **40+ verified brands**"
        ),
        inline=False
    )

    embed.add_field(
        name="🔗 Links",
        value=(
            "[GitHub Repository](https://github.com/yourusername/project)\n"
            "[Report Issues](https://github.com/yourusername/project/issues)\n"
            "[Support Server](https://discord.gg/yourserver)"
        ),
        inline=False
    )

    embed.set_footer(text="Version 1.0.0 | Developed by [Your Name]")
    embed.timestamp = discord.utils.utcnow()

    await ctx.send(embed=embed)


@bot.command(name='ping')
async def ping_command(ctx):
    """Check bot latency"""
    latency = round(bot.latency * 1000)

    if latency < 100:
        emoji = "🟢"
        status = "Excellent"
    elif latency < 200:
        emoji = "🟡"
        status = "Good"
    else:
        emoji = "🔴"
        status = "Poor"

    embed = discord.Embed(
        title=f"{emoji} Pong!",
        description=f"**Latency:** {latency}ms\n**Status:** {status}",
        color=discord.Color.green()
    )

    await ctx.send(embed=embed)


@bot.event
async def on_command_error(ctx, error):
    """Handle command errors"""
    if isinstance(error, commands.MissingRequiredArgument):
        embed = discord.Embed(
            title="❌ Missing Argument",
            description=f"You're missing a required argument: `{error.param.name}`\n\nUse `!help` for more information.",
            color=discord.Color.red()
        )
        await ctx.send(embed=embed)

    elif isinstance(error, commands.CommandNotFound):
        embed = discord.Embed(
            title="❌ Unknown Command",
            description="That command doesn't exist!\n\nUse `!help` to see available commands.",
            color=discord.Color.red()
        )
        await ctx.send(embed=embed)

    else:
        embed = discord.Embed(
            title="❌ Error",
            description=f"An error occurred: {str(error)}",
            color=discord.Color.red()
        )
        await ctx.send(embed=embed)
        print(f"Error: {error}")


# Run the bot
if __name__ == "__main__":
    token = os.getenv('DISCORD_BOT_TOKEN')

    if not token:
        print("❌ Discord bot token not found in .env file!")
        print("Please add DISCORD_BOT_TOKEN to your .env file")
    else:
        try:
            bot.run(token)
        except discord.LoginFailure:
            print("❌ Invalid Discord bot token!")
        except Exception as e:
            print(f"❌ Failed to start bot: {e}")