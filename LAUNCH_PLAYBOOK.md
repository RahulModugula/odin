# Open-Source Developer Tool Launch & Marketing Playbook (2026)

Based on research of viral launches (ruff, uv, bun, biome, aider, ast-grep, VHS, and 2025-2026 trending projects).

---

## Table of Contents

1. [Pre-Launch Checklist](#1-pre-launch-checklist)
2. [The Viral README Formula](#2-the-viral-readme-formula)
3. [Show HN Strategy](#3-show-hn-strategy)
4. [Reddit Strategy](#4-reddit-strategy)
5. [Twitter/X & Bluesky Strategy](#5-twitterx--bluesky-strategy)
6. [The "One Chart" Strategy](#6-the-one-chart-strategy)
7. [GitHub Trending & Stars](#7-github-trending--stars)
8. [Demo GIFs & Videos](#8-demo-gifs--videos)
9. [Blog & Dev.to Strategy](#9-blog--devto-strategy)
10. ["Awesome" List Inclusion](#10-awesome-list-inclusion)
11. [Conference & Community Strategy](#11-conference--community-strategy)
12. [Launch Timing](#12-launch-timing)
13. [Case Studies: What Made These Tools Go Viral](#13-case-studies)
14. [Day-of Launch Runbook](#14-day-of-launch-runbook)
15. [Post-Launch Growth Engine](#15-post-launch-growth-engine)

---

## 1. Pre-Launch Checklist

Everything that must be in place **before** you announce:

### Repository Essentials
- [ ] **README.md** — Follows the viral formula (see section 2)
- [ ] **LICENSE** — MIT or Apache 2.0 (MIT preferred for dev tools)
- [ ] **CONTRIBUTING.md** — Clear contribution guidelines
- [ ] **CHANGELOG.md** — Even if it's just "v0.1.0 - Initial Release"
- [ ] **Code of Conduct** — GitHub can auto-generate
- [ ] **Security policy** — `SECURITY.md` or GitHub security tab enabled
- [ ] **`.github/` templates** — Issue templates, PR templates
- [ ] **Topics/tags** on the repo — All relevant keywords for discoverability

### Distribution & Install
- [ ] **One-line install** — `curl | sh`, `brew install`, `pip install`, `npm install -g`
- [ ] **Multi-platform binaries** — macOS (Intel + ARM), Linux (x64 + ARM), Windows
- [ ] **Docker image** — `docker run ...` should work immediately
- [ ] **Package managers** — Homebrew, pip, npm, cargo, whatever is appropriate
- [ ] **No signup required** — HN explicitly warns against barriers

### Documentation
- [ ] **Docs site** — Even a single-page docs site (Mintlify, VitePress, mkdocs)
- [ ] **Quick start guide** — 3 steps or fewer to "aha moment"
- [ ] **Examples directory** — Real, runnable examples
- [ ] **API reference** (if applicable)

### Social & Community
- [ ] **GitHub Discussions enabled** — For Q&A and community
- [ ] **Discord server** — For real-time community (most viral projects have one)
- [ ] **Twitter/X account** — Dedicated handle for the project
- [ ] **Landing page** — Single page with value prop + demo + install command
- [ ] **Logo/branding** — Even simple, consistent visual identity matters

### Technical Credibility
- [ ] **CI/CD green** — All tests passing
- [ ] **Benchmark results** — If performance is a selling point
- [ ] **Comparison table** — vs. alternatives (see "One Chart" strategy)
- [ ] **Known adopters** — Even if it's just your own projects initially
- [ ] **Pre-commit hook** or **GitHub Action** — Easy integration path

---

## 2. The Viral README Formula

The README is your landing page. Analyzing the most-starred dev tool repos (ruff at 47k, VHS at 19.4k, bun at 75k+), the pattern is clear:

### Structure (Top to Bottom)

```
1. PROJECT NAME + ONE-LINE TAGLINE
2. Hero demo GIF/video (THE most important element)
3. Badges (build status, version, license, downloads)
4. 3-5 killer feature bullets with emoji
5. Quick install (one command)
6. Quick start example (3 lines of code, ~30 seconds to "wow")
7. Comparison chart / benchmark chart
8. Testimonials / Notable users
9. Table of contents + link to full docs
10. Detailed usage / configuration
11. Contributing + License
```

### What Makes a README Go Viral

**The Hero Demo (Critical)**
- Must be **above the fold** — visible without scrolling
- GIF or video, never a static screenshot
- Should show the "before/after" or "with/without" in under 10 seconds
- Use dark terminal theme (looks better in GitHub's default theme)
- Keep file size under 5MB for fast loading

**The One-Liner**
- Must be specific and comparative: "10-100x faster than Flake8" (ruff)
- NOT vague: "A better linter"
- Include the "written in Rust" / "written in Go" signal if applicable — developers associate Rust/Go with performance

**The Feature Bullets**
- Lead with the most differentiated feature
- Use concrete numbers: "800+ built-in rules", "10-100x faster"
- Each bullet should answer "why should I care?"

**Social Proof Block**
- "Used by" section with recognizable logos/names
- Testimonial quotes from known developers
- Ruff's README has 6+ testimonials from creators of competing tools (!)
- This is incredibly powerful — get the creator of the tool you're replacing to say something nice

**The "Drop-in Replacement" Signal**
- If you replace an existing tool, say so explicitly: "Drop-in replacement for X"
- Show a migration guide: `sed -i 's/old-thing/new-thing/g'`

### README Anti-Patterns
- Walls of text before any code example
- No visual demo
- Vague descriptions ("fast", "modern", "powerful")
- Requiring signup/login to try
- Broken badges or empty sections

---

## 3. Show HN Strategy

### What HN Users Want (from the official guidelines)
- Something they can **run on their computers** right now
- No signups, no email walls, no barriers
- Non-trivial — not a weekend one-off
- Personal — something you built and can discuss
- Early stage is fine — HN is comfortable with rough edges

### Title Format
```
Show HN: ProjectName – One-line description with specific claim
```
Examples that hit front page:
- "Show HN: Ruff – An extremely fast Python linter, written in Rust"
- "Show HN: VHS – Write terminal GIFs as code"
- "Show HN: Libretto – Making AI browser automations deterministic" (119 pts)
- "Show HN: LangAlpha – What if Claude Code was built for Wall Street?" (144 pts)

### Title Rules
- **Include the specific claim** ("10x faster", "in Rust", "for X")
- **Include the language/ecosystem** ("Python linter", "Go library")
- **Don't use marketing language** — no "revolutionary", "game-changing"
- **Do use comparison language** — "replacement for X", "alternative to Y"
- Keep under 80 characters

### What Gets Upvoted (patterns from 2025-2026 front-page Show HNs)
1. **Performance claims with proof** — "100x faster" + benchmark chart in comments
2. **"Written in Rust"** — This is a consistent signal that gets attention
3. **Replacing a hated tool** — Positioning as the better alternative
4. **AI/LLM tooling** — Anything in the AI dev tools space gets extra attention in 2025-2026
5. **Terminal/CLI tools** — HN loves CLI tools disproportionately
6. **Security tools** — Always welcome (e.g., RedSun got 146 pts, Hiraeth AWS emulator got 31 pts)
7. **Quirky/novel approaches** — MacMind (transformer in HyperCard) got 55 pts for novelty

### Comment Strategy
- **Be the first commenter** on your own post with technical details
- Share the "why I built this" story
- Include benchmark data or comparison tables
- Be present and responsive for the first 2-3 hours
- Answer every comment — HN rewards engaged creators
- Be technically honest about limitations — HN can smell BS
- **Never ask friends to upvote** — HN will penalize this

### Timing for HN
- **Tuesday through Thursday** — Best days for tech content
- **8:00-9:00 AM ET** — Catches both US East Coast morning and European afternoon
- **Avoid**: Friday afternoon, weekends, US holidays
- Avoid posting when major news is breaking (new Claude model, etc.)

---

## 4. Reddit Strategy

### Subreddit Tier List for Dev Tools

**Tier 1 — Post here first:**
| Subreddit | Subscribers | What Works | Notes |
|-----------|-------------|------------|-------|
| r/programming | 6M+ | Technical posts with benchmarks | No direct promo — frame as "I built X that does Y" |
| r/selfhosted | 1M+ | Self-hostable tools, Docker-friendly | Include docker-compose, screenshots |
| r/LocalLLaMA | 500K+ | AI/LLM-related tools | Very engaged community, loves benchmarks |
| r/coding | 1M+ | Beginner-friendly tools | Simpler explanations |
| r/webdev | 2M+ | Web dev tools | Must be directly relevant |
| r/python, r/rust, r/golang, r/javascript | Varies | Language-specific tools | Must be relevant to that language |

**Tier 2 — If relevant:**
| Subreddit | Best For |
|-----------|----------|
| r/netsec | Security tools |
| r/devops | CI/CD, infrastructure tools |
| r/opensource | Open source philosophy |
| r/SideProject | Personal story + tool |
| r/coolgithubprojects | Direct project sharing |
| r/commandline | CLI tools |
| r/git | Git-related tools |

**Tier 3 — Niche but high engagement:**
| Subreddit | Best For |
|-----------|----------|
| r/github | GitHub-related tools |
| r/vscode | Editor extensions |
| r/neovim | Neovim plugins |
| r/artificial | AI tools (broader) |
| r/MachineLearning | ML-related tools |

### Reddit Posting Rules

**Title format:**
```
"I built [tool] that [does specific thing] — [differentiator]"
```
NOT: "Check out my new tool!"

**What works on Reddit in 2026:**
- Include **screenshots or GIF** in the post body
- Write the **backstory** — "I was frustrated with X, so I built Y"
- Include **benchmark data** if applicable
- Cross-post to relevant subreddits after 24-48 hours
- Post on **Sunday or Monday** for r/programming (less noise)
- Post the **source code link** prominently

**What gets you downvoted/banned:**
- Obvious self-promotion without value
- Posting to too many subreddits at once (spam filter)
- Not reading subreddit rules first (r/programming has strict rules)
- Marketing language ("revolutionary", "best-in-class")
- Not engaging with comments
- Reposting the same content

**The Reddit Script:**
1. Day before launch: Post a "I'm building X, what features would you want?" in relevant subs (builds goodwill + awareness)
2. Launch day: "I built X — [specific value prop]" with GIF + benchmarks
3. 48 hours later: Cross-post to adjacent subreddits
4. 1 week later: "One week later — here's what I learned launching X" (r/programming loves these)

---

## 5. Twitter/X & Bluesky Strategy

### Twitter/X

**Account setup:**
- Dedicated project handle (not your personal account)
- Profile: Project name + tagline + link to repo
- Banner: Demo GIF or key visual
- Pin a tweet with the demo GIF + install command

**Tweet templates that work for dev tools:**
```
Template 1 — The Demo Drop
[Demo GIF]
One command to install: `curl -fsSL ... | sh`
What it does: [one line]
Why it's different: [one line]
GitHub: [link]

Template 2 — The Comparison
I was tired of [problem] with [existing tool]
So I built [your tool]
Same features, [X]x faster
Here's the proof: [benchmark chart]
[Link]

Template 3 — The "Just Shipped"
Just shipped [tool] v0.1.0
- Feature 1
- Feature 2
- Feature 3
Star it on GitHub: [link]
```

**Twitter growth tactics:**
- Tag influential developers who might be interested
- Quote-tweet with your own take on relevant industry news
- Post short demo videos (under 60 seconds)
- Thread format: "I spent [time] building X. Here's what it does: 🧵"
- Engage with people who post about competing tools — offer your alternative
- Use `#BuildInPublic` for ongoing development updates
- Post star milestones: "Just hit 1K stars! Here's the story..."

**Timing:** 9-10 AM ET, 12-1 PM ET, or 5-6 PM ET on weekdays

### Bluesky
- Growing rapidly in developer community
- Same content as Twitter, but tone can be more technical
- Developer audience is more concentrated than Twitter
- Less algorithmic — good content surfaces more fairly
- Cross-post to both platforms

---

## 6. The "One Chart" Strategy

This is the single most effective viral asset for a dev tool launch.

### The Concept
Create ONE comparison chart that makes your tool look dramatically better than alternatives. This chart will be shared everywhere — Reddit, HN comments, Twitter, blog posts.

### Chart Types That Go Viral

**1. Performance Benchmark Bar Chart (The Ruff Strategy)**
- What ruff used: A bar chart showing ruff completing in 0.4 seconds vs. competitors taking 20+ seconds
- This single chart sold ruff to the Python ecosystem
- Must be: Honest, reproducible, using real-world workloads
- Include methodology (hardware, dataset, versions)
- Make it embeddable in the README

**2. Feature Comparison Table**
- Rows: Features. Columns: Tools. Green checks and red X marks.
- Your tool should have a column of all green checks
- Be honest — don't omit features you don't have, mark them as "planned"

**3. Speed Over Time / Line Chart**
- Shows how your tool scales with input size vs. alternatives
- Proves performance isn't just a microbenchmark

**4. Bundle Size / Resource Usage Chart**
- For web tools: kB comparison
- For CLI tools: Memory usage, binary size
- For CI tools: Pipeline run time comparison

### Design Rules
- **Dark theme** — Matches GitHub dark mode, looks more technical
- **Minimal labels** — Let the data speak
- **Highlight your tool** — Use a bright accent color for your bar, muted colors for others
- **Include numbers** — Don't just show relative bars, show actual numbers
- **SVG format** — Crisp at any size, loads fast in README
- **Under 500px wide** — Must display well on mobile

### How to Make It Shareable
- Host it as an SVG in the repo (like ruff does at `assets/badge/`)
- Include it in the README at the top
- Post it separately on Twitter/Reddit
- Include it in Show HN comments
- Make the benchmark reproducible (script in the repo)

---

## 7. GitHub Trending & Stars

### How GitHub Trending Works
GitHub's trending algorithm considers:
- **Star velocity** — Stars per day, not total stars
- **Recency** — Recent activity weighted heavily
- **Contributors** — Multiple contributors helps
- **Activity** — Commits, issues, PRs, discussions

### Star Growth Tactics

**0 → 100 Stars (Seed Phase)**
- Personal network: Ask colleagues and friends to star
- Cross-post to all social channels simultaneously
- Post in relevant Discords and Slacks
- Submit to Hacker News (Show HN)
- Reddit posts in 3-5 relevant subreddits
- Blog post announcement

**100 → 1,000 Stars (Growth Phase)**
- Get picked up by newsletters: Hacker Newsletter, TLDR, Bytes (JavaScript Weekly), Python Weekly
- Dev.to or blog post tutorial
- Get included in "awesome" lists
- Celebrity endorsement: Get a well-known dev to try it and tweet
- Conference talk or meetup presentation
- Integration with popular tools (pre-commit, GitHub Actions)

**1,000 → 5,000 Stars (Viral Phase)**
- Major version release with blog post
- "Used by" section with big-name adopters
- Comparison blog posts ("Why I switched from X to Y")
- Podcast appearances
- Conference talks at major events
- Hacker News front page (regular submission, not Show HN)
- ProductHunt launch (less effective for dev tools, but still has reach)

**5,000+ Stars (Established Phase)**
- GitHub Sponsor program
- Corporate adoption stories
- Paid tiers / enterprise features
- Regular release cadence builds trust
- Community contributions drive organic growth

### Getting on GitHub Trending
1. **Launch on Tuesday-Thursday** — Higher natural traffic
2. **Get 50+ stars in the first 24 hours** — This triggers the algorithm
3. **Have 3+ contributors** — Even small contributions count
4. **Create a release on launch day** — Tags/releases signal activity
5. **Enable Discussions** and create 2-3 seed discussions
6. **Star velocity matters more than total** — 50 stars in 1 day > 200 stars over 2 months
7. **Multiple commits on launch day** — Shows active development
8. **Use GitHub's topic tags** — These help with discovery

---

## 8. Demo GIFs & Videos

### Why This Matters
The demo GIF is the single most viewed asset. VHS (charmbracelet) has a beautiful animated demo as its hero image. Ruff shows a benchmark chart. Every top-starred project has visual proof.

### Tools for Creating Demos

| Tool | Use Case | Notes |
|------|----------|-------|
| **VHS** (charmbracelet) | Terminal GIFs from code | Deterministic, repeatable, stores `.tape` files in repo |
| **asciinema** | Terminal recordings | Lightweight, can embed as SVG |
| **ttygif** | Terminal to GIF | Simple, works well |
| **LICEcap** | Screen recording to GIF | macOS/Windows |
| **Kap** | Screen recording to GIF | macOS, open source |
| **Screen Studio** | Polished demo videos | macOS, paid, but very professional |
| **Carbon** | Code snippets as images | For sharing on social media |

### Demo GIF Best Practices
- **Under 10 seconds** — People won't watch longer
- **Under 5MB file size** — Must load quickly in README
- **Show the "aha moment"** — The single most impressive thing your tool does
- **Use a nice terminal theme** — Catppuccin, Dracula, Tokyo Night
- **Large enough font** — Readable on mobile
- **No audio needed** — GIF is better than video for README (autoplay, no click needed)
- **Include the input and output** — Show what you type and what happens

### For Social Media
- **Videos > GIFs** on Twitter/X (autoplays with more visibility)
- Keep under 60 seconds
- Add text overlays explaining what's happening
- Use Screen Studio or similar for polished look

---

## 9. Blog & Dev.to Strategy

### Launch Blog Post Structure
```
Title: [Specific claim about your tool] (e.g., "Python tooling could be much, much faster")

1. The Problem (what's broken about the current state)
2. The Solution (your tool, one paragraph)
3. The Demo (GIF/video showing it in action)
4. The Benchmarks (comparison chart)
5. Design Philosophy (why you made key decisions)
6. Getting Started (install + quick start)
7. What's Next (roadmap, call for contributors)
8. Acknowledgements
```

### Dev.to Specific Tips
- Use the **#showdev** tag for project launches (this is the correct tag)
- Do NOT use #opensource just for promoting your project (per their guidelines)
- Cross-post your blog post to Dev.to — don't write a separate one
- Include the same demo GIF and benchmarks
- Engage with comments (Dev.to community is very supportive)
- Best posting time: Tuesday-Thursday, 9 AM ET

### Blog Platforms to Consider
- **Your own domain** (preferred — builds your brand)
- **Dev.to** (syndicate here — large developer audience)
- **Medium** (less developer-focused, but syndicate anyway)
- **Hashnode** (growing developer blogging platform)

### Blog Post Timing
- Publish the blog post **1-2 hours before** you post to HN/Reddit
- This gives you a URL to share in posts
- The blog post should be the canonical URL for the launch
- Share the blog post URL, not the GitHub URL, on HN (blog posts with context do better)

---

## 10. "Awesome" List Inclusion

### Strategy
1. **Find relevant awesome lists** — Search GitHub for `awesome-[topic]`
2. **Read their contribution guidelines** — Most have strict criteria
3. **Submit a PR** — Add your project following their format
4. **Be a good citizen first** — Contribute to the list before asking to be added

### Key Awesome Lists for Dev Tools
- awesome-selfhosted
- awesome-cli-apps
- awesome-opensource
- awesome-[your-language]
- awesome-security (if applicable)
- awesome-ai-tools
- awesome-developer-tools

### How to Get Added
- Your project should have a certain maturity (not day-old)
- Include a clear description following their format
- Some lists require minimum star counts
- Maintainers may take weeks to merge — be patient
- Don't spam multiple lists at once

---

## 11. Conference & Community Strategy

### For AI Code Review Tools (Specific)

**Top-tier conferences:**
- PyCon, RustConf, GopherCon, JSConf (language-specific)
- KubeCon / CloudNativeCon (if infrastructure)
- DEF CON / Black Hat / RSA (if security)
- AI Engineer World's Fair
- NeurIPS / ICML workshops (if research component)

**Developer conferences with CFPs:**
- FOSDEM — Free, open source, Brussels, February
- OSCON — Open source conference
- All Things Open — October, Raleigh NC
- Strange Loop — St. Louis (if running)
- GOTO Conferences — Multiple locations
- DevOpsDays — Many locations, many dates

**Meetup strategy:**
- Local Python/Rust/Go/JS meetups
- DevOps meetups
- Security meetups (BSides events)
- Offer to give a 10-20 minute talk
- Bring stickers (seriously — stickers are powerful)
- Demo live if possible

**Podcast circuit:**
- The Changelog
- Software Engineering Daily
- Developer Voices
- Syntax (web dev)
- Talk Python to Me
- Rustacean Station
- Go Time

---

## 12. Launch Timing

### Best Day to Launch
**Tuesday or Wednesday**

- Monday: People are catching up on email
- Tuesday: Fresh, engaged, looking for new things ✅
- Wednesday: Still good, slightly less competitive ✅
- Thursday: Acceptable, but people are wrapping up the week
- Friday: Avoid — people are mentally checking out
- Weekend: Avoid — lower HN/Reddit traffic, fewer developers online

### Best Time to Launch
**8:00 - 9:00 AM ET (1:00 - 2:00 PM GMT)**

This catches:
- US East Coast: Starting their day
- US West Coast: Still morning
- Europe: Afternoon, post-lunch browsing
- Asia: Evening (lower priority but still covered)

### Avoid Launching On/Before
- Major tech events (Apple WWDC, Google I/O, re:Invent)
- Major AI model releases (GPT launches, Claude launches — these dominate HN)
- US holidays (Thanksgiving, Christmas, July 4th)
- April 1st (nobody believes anything)

### Seasonal Considerations
- **January-February**: Good — people are evaluating tools for the new year
- **March-May**: Best — conference season, lots of attention
- **June-August**: Okay — slower but less competition on HN
- **September-November**: Good — back to work energy, conference talks drive interest
- **December**: Avoid — holiday mode

---

## 13. Case Studies: What Made These Tools Go Viral

### Ruff (47K+ stars)
- **One chart strategy**: Benchmark showing 10-100x speed improvement over Flake8
- **Written in Rust**: Immediate credibility signal
- **Drop-in replacement**: "Replace Flake8 + isort + Black + 20 plugins"
- **Social proof**: Testimonials from FastAPI, Pandas, Bokeh creators IN the README
- **Constant shipping**: Charlie Marsh shipped fixes same-day, responded to issues in real-time
- **The blog post**: "Python tooling could be much, much faster" — clear thesis
- **Adopted early by major projects**: Pandas, FastAPI, Airflow — gave others FOMO
- **Badge**: Created a shareable badge for adopters' READMEs

### Bun (75K+ stars)
- **Performance obsession**: Every release had new benchmark charts
- **Big tent pitch**: "Drop-in Node.js replacement" — enormous addressable market
- **Video demos**: Jarred Sumner posted short, compelling demo videos
- **Community Discord**: Active community from day one
- **Iterated publicly**: Built in the open, responded to feedback fast

### VHS / Charmbracelet tools (19K+ stars each)
- **Beautiful branding**: Consistent, recognizable visual identity
- **The demo IS the marketing**: VHS's README IS a demo of VHS
- **Ecosystem play**: Each tool promotes the others (Bubbletea, Lip Gloss, VHS)
- **Excellent documentation**: Every Charm tool has docs that are a joy to read

### Aider
- **AI timing**: Launched into the AI coding assistant wave
- **Video demos**: Short clips showing aider editing code in real-time
- **Active on Twitter**: Daily updates, responding to users publicly
- **Discord community**: Very active support channel

### ast-grep
- **Clear positioning**: "Code search and rewrite at scale"
- **Unique angle**: AST-based — fundamentally different from regex-based tools
- **Good examples**: README shows concrete before/after code transformations
- **Multi-language**: Appeals to polyglot developers

### Biome
- **Consolidation story**: "ESLint + Prettier in one tool"
- **Performance chart**: Classic comparison showing speed improvements
- **Rust credibility**: Written in Rust, like ruff
- **Migration path**: Clear guide for switching from ESLint/Prettier

---

## 14. Day-of Launch Runbook

### T-Minus 1 Week
- [ ] Finalize README with demo GIF, benchmarks, testimonials
- [ ] Set up Discord server
- [ ] Prepare blog post (draft, review, schedule)
- [ ] Create social media accounts
- [ ] Prepare HN title (iterate on it — this matters enormously)
- [ ] Brief 5-10 friends/colleagues to star the repo on launch day
- [ ] Test install on clean macOS, Linux, Windows machines

### T-Minus 1 Day
- [ ] Do a final review of README on mobile and desktop
- [ ] Ensure CI/CD is green
- [ ] Create a GitHub release with tags
- [ ] Pre-schedule blog post publication
- [ ] Prepare Twitter thread drafts
- [ ] Prepare Reddit posts (draft but don't submit)

### Launch Day (Tuesday or Wednesday)

**8:00 AM ET** — Publish blog post
**8:15 AM ET** — Submit to Hacker News (Show HN)
**8:20 AM ET** — Post to Twitter/X
**8:25 AM ET** — Post to Bluesky
**8:30 AM ET** — Post to r/programming
**9:00 AM ET** — Post to relevant language-specific subreddits
**9:30 AM ET** — Post to Dev.to
**10:00 AM ET** — Post to r/selfhosted, r/coding (if applicable)
**12:00 PM ET** — Check HN, respond to all comments
**Throughout day** — Monitor all channels, respond within 15 minutes
**6:00 PM ET** — Post star count update on Twitter ("300 stars in 10 hours!")
**9:00 PM ET** — Post retrospective thoughts / lessons learned

### Launch Day +1
- [ ] Post to remaining relevant subreddits
- [ ] Submit to newsletters (Hacker Newsletter, TLDR, etc.)
- [ ] Cross-post blog to Dev.to if not done already
- [ ] Submit PRs to relevant "awesome" lists
- [ ] Post in relevant Discord servers and Slacks
- [ ] Start responding to GitHub Issues and Discussions

### Launch Week
- [ ] Ship at least one improvement based on launch feedback
- [ ] Write a "One week later" blog post or tweet thread
- [ ] Follow up with anyone who showed interest
- [ ] Start reaching out to podcast hosts
- [ ] Submit CFPs to relevant conferences

---

## 15. Post-Launch Growth Engine

### Weekly
- Ship at least one meaningful update
- Post a "This week in [project]" update
- Engage on Twitter and Discord
- Respond to all GitHub issues within 24 hours

### Monthly
- Write a blog post (tutorial, deep-dive, or announcement)
- Release a new version with a changelog
- Submit to at least one new "awesome" list or directory
- Record a demo video or asciinema

### Quarterly
- Major release with blog post
- Conference talk or meetup presentation
- Podcast appearance
- Review and update README with new testimonials and adopters

### Star Growth Milestones & Actions
| Milestone | Action |
|-----------|--------|
| 100 stars | Celebrate on Twitter, update README |
| 500 stars | Add "Used by" section, submit to awesome lists |
| 1,000 stars | Blog post: "How [tool] hit 1K stars", apply to GitHub Accelerator |
| 2,500 stars | Set up GitHub Sponsors, consider governance |
| 5,000 stars | Conference talk tour, enterprise features |
| 10,000 stars | You've made it. Build a company or foundation around it |

---

## Quick Reference: The Top 10 Most Impactful Things

1. **The demo GIF** — Above the fold in README, under 10 seconds, shows the "wow" moment
2. **The benchmark chart** — One chart that proves your claim (the "Ruff strategy")
3. **Show HN on Tuesday at 8 AM ET** — Single best launch channel for dev tools
4. **One-line install** — `curl | sh` or `brew install` with zero friction
5. **Testimonials in README** — From recognizable developers, preferably creators of tools you replace
6. **Reddit on launch day** — r/programming + 2-3 relevant subreddits with different angles
7. **Twitter demo thread** — GIF + install + comparison, posted at peak hours
8. **Respond to everything in the first 48 hours** — Comments, issues, tweets, everything
9. **Ship fixes fast** — Same-day fixes for launch-day bugs = instant credibility
10. **"Drop-in replacement" positioning** — If applicable, this is the strongest marketing claim

---

*This playbook was compiled from analysis of viral open-source launches in 2023-2026, Hacker News patterns, GitHub trending algorithms, and community best practices.*
