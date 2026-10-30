# AI SOC web

This browser application uses the live service APIs. It is separate from the existing UI served by the default Docker image. Workspace deployment and integration have not been qualified.

## Install and build

From this directory, install the locked dependencies and build the application:

```sh
npm ci
npm run typecheck
npm run validators:check
npm run workspace-types:check
npm run workspace-validators:check
npm run build
```

The build writes static files to `dist/`. The validator and type checks verify the generated files against the service contracts.

## Run locally

Run `npm run dev` and open the localhost address printed by Vite. The development server uses port 5184 by default. Run `npm run preview` to serve a built application locally.

Both commands use live APIs and provide no authentication or API proxy. To use the application, supply an authenticated same-origin integration for `/v1`. The workspace commands and their content assets currently require a source checkout; wheel packaging and deployment integration have not been qualified.
