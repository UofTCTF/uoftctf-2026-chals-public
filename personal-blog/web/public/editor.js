(() => {
  const editor = document.getElementById('editor');
  const saveButton = document.getElementById('saveButton');
  if (!editor) {
    return;
  }
  const postId = editor.dataset.postId;

  const postJson = async (url, payload) => {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!response.ok) {
      throw new Error('Request failed');
    }
  };

  if (saveButton) {
    saveButton.addEventListener('click', async () => {
      try {
        await postJson('/api/save', { postId, content: editor.innerHTML });
      } catch (err) {
        // ignore
      }
    });
  }

  setInterval(async () => {
    const clean = window.DOMPurify.sanitize(editor.innerHTML);
    try {
      await postJson('/api/autosave', { postId, content: clean });
    } catch (err) {
      // ignore
    }
  }, 30000);
})();
