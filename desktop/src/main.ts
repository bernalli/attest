// The stylesheet the site already ships, imported unmodified and first, then this
// package's additions over it. Two imports, one emitted stylesheet, one inline <style>
// in the artifact — which is what the content security policy pins by hash.
import '../../site/src/styles.css'
import './desktop.css'
import { initDesktopApp } from './app.js'

// The single entry point the build inlines. It does one thing, so that the guard in
// `initDesktopApp` — which clears the failure banner only after the wiring is complete —
// is the last thing standing between a broken page and a page that claims to work.
initDesktopApp(document)
