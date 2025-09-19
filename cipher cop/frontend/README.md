Quick instructions to enable the React dashboard locally:

1. From the `cipher cop/frontend` folder install deps:

```bash
# Windows cmd.exe
cd "f:\College\Hackathons\CipherCop\cipher cop\frontend"
npm install --save-dev vite @vitejs/plugin-react
npm install react react-dom
```

2. Run the dev server:

```bash
npm run dev
```

3. Build for production:

```bash
npm run build
npm run preview
```

Notes:
- After building, `dist/index.html` will reference the compiled bundle. You can replace the root `index.html` or serve the `dist` folder.
- I created `main.jsx` as the Vite entry that mounts `App.js` into `#root`.
