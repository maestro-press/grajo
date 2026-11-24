# Trading

**Crow's Nest → Trading** is where Crow trades crypto for you through Coinbase. It is a page in the finance group of the sidebar, and it comes from the **Coinbase (Beta)** add-on on the **Extensions** page. This is a beta. Start small, practise first, and remember that the money is yours: Crow does not give financial advice, and nothing here promises a profit.

## What the Trading page is

Crow places every order through one **trading engine**, the part of the Coinbase add-on that places orders. It has limits of its own, and Crow keeps two sides: a practice side with pretend money and a live side with real money.

| Side | Badge | What it means |
|---|---|---|
| **Practice** | PRACTICE | No real money. Orders are simulated against public market prices, and they wait at a set price until the market reaches it. |
| **Live** | LIVE | Real money, in your Coinbase Crow portfolio. |

Practice is the default, and every new bot starts there; live trading is switched on separately, later. On the page you set up a **Connect** key, and below that you find **Pending approvals**, **Bots**, **Open orders** (one box per side), **Alerts**, **Recent fills and profit/loss**, **Limits in force** and **Settings**. A bot trades one pair (such as BTC-USDC) with a strategy. Crow never moves money in or out of Coinbase, and the key you give it cannot.

## Before you start (two-factor)

Everything privileged needs two-factor sign-in. Until it is on, the page says **Turn on two-factor sign-in first (Settings → Security)**. On top of that, privileged actions want you to be signed in with your password on this Crow, not through a linked device, and they want a fresh 2FA code typed into the **2FA code** box next to the button. A code can be used once; too many wrong codes and the page says *"Too many wrong codes. Try again in 15 minutes."* The code is there so that you, and only you, can start something that could move real money, and so that a session someone else got hold of cannot take a bot live.

| Action | What it needs |
|---|---|
| **Test connection** | Your password sign-in, and two-factor switched on. No code. |
| **Connect**, **Disconnect** | Password sign-in, and a fresh code. |
| Turning a live switch on | Password sign-in, and a fresh code. |
| **Go live** with a bot, **Resume trading** after a stop | Password sign-in, and a fresh code. |
| Saving limits; **Resume** or **Move the middle price** on a live bot | Password sign-in, and a fresh code. |
| **Approve** an AI order proposal | Password sign-in, and a fresh code. |
| **KILL SWITCH**, **Pause**, **Stop**, **Not now**, turning a live switch off, creating a bot, **Back to practice**, **Resume** or **Move the middle price** on a practice bot | Your password sign-in only. |

## Connect Coinbase

Install **Coinbase (Beta)** from **Extensions** first. Then, in **Connect**, the page gives you the steps to follow in Coinbase, and a form to fill in:

> 1. In Coinbase, create a portfolio named Crow and move only the money you want the bot to use. 2. Create an API key for the Crow portfolio with View and Trade. Do not tick Transfer. 3. Paste the key name and private key here. 4. Press Test connection.

1. **Project** — the Crow project that keeps the trading record. With no project made yet, it says *"No projects yet. Create one first."*, and pressing **Connect** without picking one says *"Pick a project first."*
2. **Key name** and **Private key** — both are hidden as you type.
3. **2FA code** — your current code.
4. Press **Test connection** to check the key with Coinbase without installing anything. It reads *"Key accepted — Crow portfolio …"* followed by the last four characters of the portfolio name.
5. When that looks right, press **Connect**. This stores the key sealed and starts using it. It reads *"Connected — Crow portfolio …"* and the same last four.

If a key is already connected, **Connect** answers *"Already connected. Disconnect first to use a different key."*

### When Crow refuses the key

Crow checks the key before it uses it, and tells you what to fix in plain words:

| Crow says | What to do |
|---|---|
| *"This key can move money out of Coinbase. Create a new key and leave Transfer unticked (View and Trade only)."* | Make a new key without Transfer, so it cannot move money out. |
| *"This key is not limited to one portfolio. Create the key for the Crow portfolio only."* | Make the key for the Crow portfolio itself. |
| *"This key is for your main Coinbase portfolio. Create a key for the Crow portfolio instead."* | Make a key on the Crow portfolio, not your main one. |
| *"This key is for a different portfolio than the one Crow trades. Create a key for the Crow portfolio."* | Make the key on the portfolio Crow uses. |
| *"This key can only view. Create a key with View and Trade."* | Give the key trading permission. |
| *"Coinbase did not accept this key. Check that you pasted the key name and the whole private key, with nothing added or missing."* | Paste again, carefully and in full. |

For anything else ("Too many tries", "The trading engine isn't answering", "Crow could not sign this request", "Crow could not connect to Coinbase"), wait a minute, make sure the Coinbase add-on is installed and running, and try again. If it still fails, ask for help. You move the money yourself: in the Coinbase app, put into the Crow portfolio only what you are willing to let bots and the AI use; Crow cannot do it, and the key cannot either. A bot cannot go live until that money is there and not already spoken for.

## Practice bots

Under **Bots**, a new bot form asks **What should it trade?** and **Starting money (USDC)**. The default strategy is **Rebalance**, which is the recommended one: it keeps about half in the coin and the rest in USDC. Under **More options** you can tick **Use a grid instead of rebalancing**, with a note saying *"No edge on average: it behaves like holding about half in the coin."* A grid asks for **Middle price**, **Step (%)**, **Steps below**, **Steps above**, **Money per buy (USDC)** and **Money to buy with** (either **What it just sold** or **Fresh money**).

Press **Create bot (Practice)**, and Crow answers *"Created. It practises with pretend money until you take it live."* Each bot card shows the pair and the strategy, whether it is running, paused or stopped, and then **Worth**, how far it is ahead of or behind *"simply holding your starting mix"*, **Profit taken so far** and **Fees paid**. A bot the trading engine paused says it needs attention.

- **Pause** stops it and cancels its waiting orders on Coinbase (*"Paused. Its waiting orders on Coinbase were cancelled, and it places no new ones until you resume."*). It keeps the bot, so **Resume** can start it again from the prices now, not from where it was (*"Started again from the prices now."*). If Crow cannot cancel every order it says *"Paused, but Crow couldn't cancel every waiting order on Coinbase. Press Pause again, or cancel them in the Coinbase app: Crow portfolio → Open orders."*
- **Stop** ends it (*"Stopped."*) and also cancels its waiting orders on Coinbase; a stopped bot cannot be started again, so make a new bot instead.
- **Go live** takes a practice bot to real money; a live bot shows **Back to practice** instead.
- **Move the middle price** is there for a grid bot.

Watch a Practice bot for a while before you think about real money: its worth, how it does against simply holding, its fills and its alerts.

## Going live

Live trading is a separate step, and the order matters.

1. Make the bot in Practice and watch it.
2. In **Settings**, two switches sit off by default: **Let bots trade with real money** and **Let the AI place real orders after I approve**. Turning one on needs a fresh code; turning one off needs no code. The page answers *"Bots can now trade with real money."*, *"Bots are back to practice only."*, *"The AI can now place real orders after you approve them."* or *"The AI can no longer place real orders."* Every change of either switch also sends you a priority alert. Turning a switch on with nothing connected answers *"Coinbase isn't connected, so nothing was switched."*
3. On the bot card press **Go live**, tick **I understand this bot will trade with real money.**, set **Starting money (USDC)**, type your code and press **Turn on live trading**. Without the tick the page says *"Confirm that this bot will trade with real money."*

The switch is refused if live trading is switched off for the bots, or if the Crow portfolio does not have that much free money. When it works the page says *"Live. It now trades with real money."* and the badge turns LIVE. The bot keeps the status it had before the switch (running stays running, paused stays paused). A live bot needs a fresh code for **Resume** of a paused bot and for **Move the middle price**. Turning a switch off does not cancel orders already waiting; Pause or Stop each bot to cancel them. If live trading is switched off for the whole computer in the add-on settings, the page says *"Live trading is switched off on this computer in the add-on settings. Nothing here can turn it on."*

**Back to practice** is the way back, and it sits on a live bot's card in place of **Go live**. One press, no code: it cancels that bot's orders waiting on Coinbase and does not sell anything. *"Back to practice. The bot's orders waiting on Coinbase were cancelled and it now trades with pretend money. Nothing was sold."*

## AI order proposals

Crow's trading tools can do a fair amount on their own, and nothing that spends real money without you.

| Area | What the tools can do |
|---|---|
| Look | Read the balances; list your bots; read one bot's status and profit/loss; read a bot's recent fills; read profit and loss for each bot; read the current price of a pair. |
| Run a bot | Pause a bot; resume one (Practice only); stop one; move a bot's middle price (Practice only); create a bot, which always starts in Practice. |
| Orders | Propose an order (a preview, measured against the limits, with nothing placed); check a proposal's state and get its approval link; cancel an order it placed itself. |

The tools can never approve their own proposal, take a bot live, switch live trading on or off, change a limit, reach the kill switch or clear a stop, connect or disconnect, move money, or read your key or any secret. A live bot cannot be resumed or have its middle price moved by the AI, and an order placed any other way cannot be cancelled by it. Every order it sends waits for your approval.

When the AI proposes an order, you get a priority alert titled **The AI proposed an order** with a link. The proposal also appears under **Pending approvals** with a PRACTICE or LIVE badge, a plain summary of what it would do, lines such as *"It rests on the order book and fills only at that price or better."*, the limit that applies and how much of it today's total would use, and **Time left**. A proposal stays open for 15 minutes by default; the add-on settings can change that, and answered proposals show for a while under **Recently answered**.

To answer it, type your 2FA code and press **Approve** (*"Approved. Placing your order now."*) or press **Not now** (*"Okay, not now."*, no code needed). An approval places exactly what the card showed; nothing is re-priced. If it moved in the meantime the page says *"This proposal changed. Look at it again before approving."*, and if the window closed, *"This proposal expired. Ask again."* A proposal that is gone, or one someone already answered, says so as well, and you can ask again. A proposal alert on your phone opens the Trading page with that proposal highlighted; you still need your password sign-in and a code to approve it.

## Stocks (off by default)

Stocks are off by default. Nothing about them happens until the install lists the ones it may trade, in the add-on settings; while that list is empty, Crow trades no stocks at all and no stock proposal can be made.

Once stocks are listed, the AI proposes a stock order just like a coin order, and you approve it the same way: the same alert, the same card under **Pending approvals**, the same code. A stock order is always a limit order, and it only goes out in the regular market session, so while the stock market is closed a stock order cannot be placed and the card says so. Nothing is ever sent at the market price.

The limits for stocks are separate from the limits for coins: the most for one stock order, the total for a day's stock orders, and the money set aside for AI stock trades. The proposal shows the ones that apply, says whether the stock market is open, and shows the money left for stock trades before and after this order, so you can see what room is left before you approve.

If Crow cannot confirm the stock products, for example before a key is connected, it turns stock trading off by itself, shows an alert, and keeps trading coins as usual.

Live stock trading cannot be turned on yet. It needs a confirmed order preview, which comes in a later step; until then stock orders stay in practice. If your stock holdings fall far below their high point, Crow raises an alert. It alerts only: it never stops trading on that account, and the decision stays with you.

A stock Crow no longer lists cannot be sold through Crow; sell it by hand in the Coinbase app.

## Stock prices

Crow needs a price source for stocks, because Coinbase does not give Crow stock prices. Crow uses [Tiingo](https://www.tiingo.com/), which has a free plan for personal use. Crow has not checked Tiingo's terms for you: read them yourself.

1. Make a free Tiingo account.
2. Find your API token in your account. The menu names on Tiingo's site were not checked; look for **API** or **Account**.
3. Open the Trading page and find **Stock prices (Tiingo)**.
4. Paste the token into the box; it is hidden as you type.
5. Press **Test**, then **Save**.

It only needs your password sign-in, with no 2FA code, because the token can only read prices and cannot spend or move money. Coinbase must be connected first. The card is only shown once stocks are listed in the add-on settings.

The card says one of these:

- *"Stock prices are connected (Tiingo)."*
- *"Stock prices are not connected, so practice stock orders will not fill. Paste your free Tiingo token below."*
- *"Tiingo did not accept the token. Paste it again."*
- *"Connect Coinbase first, then add stock prices."*
- *"Stock prices are paused for now (Tiingo is limiting requests); they will resume on their own."*

The card says prices are paused when Tiingo is limiting requests or when Crow has used its allowance. Nothing needs pressing: the pause ends on its own and prices come back.

**Disconnect** on this card forgets the token. It is stored sealed like your key and never shown again, and the trading engine holds it only in memory (never in a file or setting), so after an engine restart Crow sends it again by itself.

Crow asks Tiingo for a price about every 1.5 to 4 minutes, depending on how many stocks are listed: about 90 seconds per stock with one listed, 170 seconds with two and 255 seconds with three. The more stocks are listed, the longer the wait between prices, and it pauses on its own when the allowance is used. Prices are used only for practice stock fills and for display; real orders always go to Coinbase, and once live stock trading exists, live stock orders will also be checked against this price. A practice stock order accepts a price up to 5 minutes old; a live stock order, when live stock trading exists, will need a price no older than 2 minutes. Neither uses a price from outside the regular session.

Disconnecting Coinbase also forgets the stock prices token, and reconnecting Coinbase after the engine reset may need the token pasted again.

## The kill switch

The big red **KILL SWITCH** button sits at the top of the page and is always there. Press it once and it asks *"Press the kill switch again to confirm."*; press it again. No code and no two-factor: *"Stops every bot and asks Coinbase to cancel Crow's orders right away. No code needed."* It stops both sides and cancels the orders Crow placed, answering *"Stopped. Every Crow order is being cancelled and every bot is stopped. Press Resume trading when you are ready."* If Coinbase cannot be reached yet, it adds *"The kill switch can only cancel orders on Coinbase once the engine reconnects."* If it could not do the job, it says so instead of pretending: *"Nothing was stopped: the trading engine is down. Cancel open orders by hand in the Coinbase app: Crow portfolio → Open orders."*, *"Nothing was stopped: Crow couldn't reach the trading engine. Cancel open orders by hand in the Coinbase app: Crow portfolio → Open orders."*, or *"Trading is halted, but some orders may still be resting on Coinbase."* — trading is stopped then, so check Coinbase for orders waiting at a set price and cancel them by hand.

Trading also stops on its own. A side that falls too far from its best is halted, and its orders waiting at a set price are cancelled; the other side is untouched. The banner says *"Stopped. Every Crow order is being cancelled and every bot is stopped. Press Resume trading when you are ready."*, or, for one side, *"Trading on this book is stopped until you press Resume trading."*

When a stop is in force a bar appears with a **2FA code** box and **Resume trading**. Clearing a stop needs a fresh code, because it lets orders flow again. Bots the kill switch stopped stay stopped for good; create a new bot to trade again. The page answers *"Resumed. Crow may trade again. Bots that were stopped stay stopped; create a new bot to trade again."* Clearing also resets the "best" each side is measured from to where it is now, so the same fall cannot stop it again at once.

An engine check also watches the trading engine: if it stops answering you get an urgent alert titled **Trading engine not responding**, and **Trading engine is back** when it answers again. The add-on settings decide whether that check also cancels Crow's orders; by default it only alerts.

## Limits

**Limits in force** lists each limit with its fixed maximum and what has been used today. Under **Settings → More options → Limits Crow may not pass** you can lower any of them; that needs a fresh code, and the page answers *"Saved."* You can lower a limit, and raise it again only up to its fixed maximum, never above. Asking for more than that is refused: *"that is above the limit of … set in Crow's add-on settings."* Those maximums are set in the add-on settings, and this page can never raise them. Out of the box they are these, and an install can differ:

| Limit | Out of the box |
|---|---|
| Most Crow may spend in a day | 200 USD |
| Most orders an hour | 30 |
| Stop trading after this much fall from the top | 20 percent |
| Largest single order from a bot | 50 USD |
| Most starting money for a new bot | 100 USD |
| Largest single order from the AI | 25 USD |
| Most the AI may spend in a day | 50 USD |
| Most AI orders an hour | 10 |
| Most money the AI may manage | 25 USD |

By default the products allowed are BTC-USDC, ETH-USDC and XRP-USDC. If you set the fall-from-the-top limit to something today's fall already reaches, Crow warns *"This halts live trading now. Press Save again to confirm."* (or *"...practice trading now..."*) and saves nothing until you press Save again. Crow also rings the bell if a bot does worse than simply holding its starting mix, and suggests pausing it: **Bot is behind simply holding**. The number of days that takes is set in the add-on settings (7 by default).

## Phone alerts

Trading events arrive as Crow notifications, and reach your phone through the push you set up in [Notifications & Push](./notifications).

| Alert | Urgency | When |
|---|---|---|
| Trading halted | Urgent | A side was stopped. |
| Trading engine watchdog | Urgent | The trading engine stopped answering. |
| Trading engine not responding | Urgent | The trading engine has stopped answering. |
| Coinbase connection needs attention | Urgent | The connection has a fault. |
| Live trading switch changed | Urgent | You turned a live switch on or off. |
| The AI proposed an order | Urgent | An order is waiting for your approval. |
| Trading alert | Urgent | Something else about trading wants your eyes. |
| Order filled | Normal | One of Crow's orders filled. |
| Bot is behind simply holding | Normal | A bot is doing worse than simply holding on. |
| A bot needs attention | Normal | The trading engine paused a bot. |
| Trading engine is back | Normal | The trading engine answers again. |
| Trading engine was reset | Urgent | The trading engine lost its saved connection to Coinbase; reconnect in the Trading panel. |
| Trading engine history was reset | Normal | The trading engine lost some of its saved history; some earlier events cannot be shown. |

To keep the bell readable, each everyday kind sends at most 6 notices an hour; the rest are folded into one summary note per kind per hour. AI proposals are different: up to 20 an hour arrive one by one, and any more are folded into one priority summary an hour: *"… more AI order proposals waiting - open the Trading panel"*. Stops, switch changes, engine checks and connection alerts are never held back.

## Disconnecting

Once you are connected, the **Connect** box is replaced by a connected view. It shows *"Connected — Crow portfolio …"* with the last four characters of the portfolio name, then the last four characters of the key, a **2FA code** box and **Disconnect**. Disconnecting is refused while live trading is still open: with live orders waiting it says *"Pause or stop live bots first"*, and with a live bot or the AI live switch still on it says *"Switch live bots back to practice mode first."* Press **Pause**, **Back to practice** or **Stop** on each live bot, and turn off **Let the AI place real orders after I approve**, then Disconnect again.

If it fails halfway, press **Disconnect** again: *"Disconnect didn't finish — press Disconnect again"*. When it works: *"Disconnected."* Disconnect does not delete the key at Coinbase; if you want the key gone, delete it in Coinbase yourself. Disconnecting Coinbase also forgets the stock prices token, so the card asks for it again before practice stock orders can fill.

If the trading engine loses its saved connection (after a reinstall or a reset, say), the page says *"Crow lost its link to the trading engine. Press Connect again."* and a notification tells you to reconnect in the Trading panel. Paste your key name and private key again, since Crow does not hand them back. If the trading engine does not answer, the page says *"Trading engine is not responding."*

## Privacy

The key name, the private key, the approval secret and the stock prices token are stored sealed. None of them is ever shown again: the page shows only the last four characters of the key and of the portfolio. The AI's tools cannot read them, and connecting does not open your saved secrets.