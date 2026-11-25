# Self Service
<!-- group: Deploy and patch; order: 32; pages: /catalog -->

Let people install approved software on their own computer, without a ticket. Every endpoint with the agent has a **Mustra Self Service** app; it lists the packages you offer to that endpoint.

## Before you start

- Offering packages and deciding requests needs **Deploy software and run actions** (`deploy.manage`).
- The package must have a published version. See [Deploy software](deploy-software.md).

## Offer a package

1. Open the package in **Deploy → Software Catalog**.
2. Tick **Offer in Self Service**.
3. Choose who sees it with the package's computer groups: no groups means every endpoint.
4. Choose whether Self Service follows the latest published version, or stays on one version you pin.
5. Save. The package appears under **Self Service → Offered packages**, and on those endpoints within a minute.

## Categories

People find software faster when it is sorted. **Self Service → Categories** lists the sections the window shows beside **All**: Browsers, Productivity, Communication, Developer tools, Utilities and Security to start with.

1. Add a category with a name and, if you like, an icon. Rename it, change its icon, move it up or down, or delete it from its row.
2. File a package under categories in its **Catalog settings** under **Deploy → Software Catalog**: tick as many as fit.
3. A package in no category appears under **All** and **Other**. The window only shows categories that something offered to that computer is in.

Endpoints see changes the next time the window is opened. Agents from before categories show one category per package.

## Requests

Tick **Endpoints outside its groups may request it** on a package, and people on other endpoints see it in Self Service with a **Request** button instead of **Install**. Their requests appear under **Self Service → Requests**. Choose **approve** to install it on that computer, or **deny**.

## What people see

- **Windows:** **Mustra Self Service** in the Start menu and on the Desktop.
- **macOS:** **Mustra Self Service** in Applications.

They choose a package and **Install**. The window shows progress and the result, and the installation appears in **Deploy → Deployments** like any other.

## Make it look like yours

**Self Service → Self Service appearance** sets the name, logo, colours, a help link and the order of sections people see. Choose **Save and publish** to send it to endpoints, or **Discard changes**. **Download appearance** and **Upload appearance…** move a look between servers.
