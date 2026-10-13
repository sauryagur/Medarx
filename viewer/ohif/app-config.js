/**
 * The Medarx OHIF application configuration.
 *
 * This is the file OHIF's dev server loads as `APP_CONFIG`
 * (`platform/app/.webpack/webpack.pwa.js`, which copies
 * `public/<APP_CONFIG>` to `app-config.js` in the served output). It is
 * configuration — data, not a patched OHIF file — and it is the whole of what
 * the mount needs on the host side:
 *
 *   1. a DICOMweb data source pointing at Orthanc, and
 *   2. a customization that places the Medarx panel in the longitudinal mode's
 *      right-hand panel list.
 *
 * ## The data source is a display source
 *
 * `imageRendering: 'wadors'` means the browser fetches image data from Orthanc
 * **and renders it in the viewport**. That is the point: the clinician reads
 * images in OHIF, the way they always have. Nothing in Medarx reads a pixel.
 * This configuration creates no path from a frame to the Medarx API or to the
 * panel — the panel is a DOM sibling of the viewport and nothing else.
 *
 * ## Why the panel is placed by customization and not by editing the mode
 *
 * The longitudinal mode declares its `rightPanels` literally
 * (`modes/longitudinal/src/index.ts`). OHIF seeds that list into the
 * customization service at mode scope and then layers the app config's
 * `mode`-phase blocks on top (`platform/app/src/routes/Mode/Mode.tsx`), so a
 * client can add a panel without the mode's source being edited. The
 * `rightPanels` value is re-applied to the panel service whenever the resolved
 * list differs from the mode's own, which is what puts the panel in the
 * sidebar.
 *
 * The block is keyed by `viewer`, the mode's **routeName**, and by nothing
 * else. The mode is also addressable by its id, `@ohif/mode-longitudinal`, and
 * `applyModeCustomizations` is handed both — keying the block to both would
 * apply it twice and put the panel in the list twice.
 */
/** @type {AppTypes.Config} */
window.config = {
  routerBasename: null,
  extensions: [],
  modes: [],

  showStudyList: true,
  showLoadingIndicator: true,
  showCPUFallbackMessage: true,
  showWarningMessageForCrossOrigin: false,
  strictZSpacingForVolumeViewport: false,
  maxNumberOfWebWorkers: 3,

  // Research and demonstration only. The OHIF app asks the reader to confirm
  // this on first load; the project's own positioning says the same thing in
  // `contracts/openapi.yaml` at `info/description`.
  investigationalUseDialog: { option: 'always' },

  defaultDataSourceName: 'orthanc',
  dataSources: [
    {
      namespace: '@ohif/extension-default.dataSourcesModule.dicomweb',
      sourceName: 'orthanc',
      configuration: {
        friendlyName: 'Local Orthanc (synthetic studies only)',
        name: 'MEDARX-ORTHANC',
        // **Same-origin, through the dev server's proxy.** Measured on this
        // host 2026-09-28: Orthanc 1.10.1's DICOMweb plugin sends no
        // `Access-Control-Allow-Origin` header at all, so a direct
        // `http://127.0.0.1:8042` data source is blocked by the browser
        // before a request is ever made. OHIF's dev server proxies `PROXY_*`
        // (`platform/app/.webpack/webpack.pwa.js`, and the stock
        // `dev:orthanc` script), so `/pacs/dicom-web` is same-origin and the
        // browser's CORS rules are never engaged. The far side of the proxy
        // is our forwarder: the request reaches the container, is handed to
        // Orthanc on its loopback, and Orthanc still believes it is local.
        wadoUriRoot: '/pacs/dicom-web',
        qidoRoot: '/pacs/dicom-web',
        wadoRoot: '/pacs/dicom-web',
        qidoSupportsIncludeField: true,
        supportsFuzzyMatching: false,
        supportsWildcard: true,
        // Rendering, both of them, into the viewport. No pixel data crosses
        // into any Medarx surface; this is the viewer's own image path.
        imageRendering: 'wadors',
        thumbnailRendering: 'rendered',
        thumbnailRequestStrategy: 'fetch',
        enableStudyLazyLoad: true,
      },
    },
    {
      namespace: '@ohif/extension-default.dataSourcesModule.dicomjson',
      sourceName: 'dicomjson',
      configuration: { friendlyName: 'dicom json', name: 'json' },
    },
    {
      namespace: '@ohif/extension-default.dataSourcesModule.dicomlocal',
      sourceName: 'dicomlocal',
      configuration: { friendlyName: 'dicom local' },
    },
  ],

  customizationService: {
    /**
     * The `mode` phase. Applied on entering the longitudinal mode, layered over
     * the mode's own seeded `rightPanels`.
     *
     * `$push` is immutability-helper's directive and is what the
     * CustomizationService applies to a customization value
     * (`platform/core/src/services/CustomizationService/CustomizationService.ts`).
     */
    mode: {
      viewer: {
        rightPanels: {
          $push: ['@ohif/extension-medarx.panelModule.medarxPanel'],
        },
      },
    },
  },
};
