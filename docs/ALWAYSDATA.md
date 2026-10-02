# alwaysdata free WSGI deployment

This is a single Python WSGI website with a local SQLite database. It does not
run Watchtower's continuous source threads. Visitors create bounded synthetic
traffic with **Simulate Attack**; `/api/v1/system-health` reports idle between
simulations. Do not describe this host as live network monitoring.

1. Create a Free personal alwaysdata account. Set **Environment → Python** to
   **3.13**. The free account has 1 GB disk and 256 MB RAM; check usage after
   dependency installation. The free plan is for personal, non-profit use.
2. In **Remote access → SSH/SFTP**, use the account's existing SSH user.
   Connect to `ssh-<account>.alwaysdata.net`. Keep the SSH password out of
   scripts and chat.
3. On the host, clone this branch into `/home/<account>/watchtower`. Create a
   virtual environment and install the pinned runtime requirements:

   ```sh
   git clone --branch codex/watchtower-public-demo https://github.com/Shlok014/watchtower.git ~/watchtower
   python -m venv ~/watchtower-venv
   ~/watchtower-venv/bin/python -m pip install -r ~/watchtower/backend/requirements.txt
   ```

4. The deployment branch includes a prebuilt `frontend/dist` bundle so the
   1 GB host does not need Node.js or `node_modules`. For updates, rebuild it
   locally from the same checkout, then commit the new bundle:

   ```sh
   cd frontend
   npm ci
   VITE_PUBLIC_DEMO=1 VITE_API_URL=/api/v1 npm run build
   ```

   The generated directory is normally Git-ignored; use `git add -f
   frontend/dist` on this deployment branch. Verify the site serves the new
   hashed assets after pulling.
5. In **Web → Sites**, edit the new account's default site (or create one at its
   `*.alwaysdata.net` address). Set type **Python WSGI**, application path
   `/home/<account>/watchtower/wsgi.py`, working directory
   `/home/<account>/watchtower`, Python **3.13**, and virtualenv directory
   `/home/<account>/watchtower-venv`. The entrypoint forces public-demo mode and
   disables continuous sources. By default it stores state at
   `/home/<account>/watchtower-data`; set `WATCHTOWER_DATA_DIR` in the site
   configuration only if a different persistent home-directory path is needed.
6. Open the public URL anonymously. Check `/`, `/api/v1/stats`, and
   `/api/v1/system-health`. Confirm `POST /api/v1/reset` and
   `POST /api/v1/retrain` return 403. Trigger one synthetic attack, verify that
   its events and ledger survive an app restart, and confirm the site still
   serves the dashboard after that restart.

To update code, build and commit `frontend/dist` locally, pull the branch on
the host, and restart the site.
Keep `~/watchtower-data` outside the checkout. A small shared history can be
cleared as maintenance if disk usage grows; tell visitors if it is cleared.
The free account requires occasional admin logins to avoid suspension.
