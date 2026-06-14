"""
CipherVault - AES-256 Encryption Tool
Requires: pip install cryptography
Run:      python cipher_vault.py
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import base64, os, threading
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ─── Crypto helpers ───────────────────────────────────────────────────────────

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=310_000, backend=default_backend()
    )
    return kdf.derive(passphrase.encode())


def encrypt_aes_gcm(data: bytes, passphrase: str) -> bytes:
    salt = os.urandom(16)
    iv   = os.urandom(12)
    key  = derive_key(passphrase, salt)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ct = AESGCM(key).encrypt(iv, data, None)
    return b'\x01' + salt + iv + ct


def decrypt_aes_gcm(data: bytes, passphrase: str) -> bytes:
    salt, iv, ct = data[1:17], data[17:29], data[29:]
    key = derive_key(passphrase, salt)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(iv, ct, None)


def encrypt_aes_cbc(data: bytes, passphrase: str) -> bytes:
    salt = os.urandom(16)
    iv   = os.urandom(16)
    key  = derive_key(passphrase, salt)
    pad  = padding.PKCS7(128).padder()
    padded = pad.update(data) + pad.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return b'\x02' + salt + iv + ct


def decrypt_aes_cbc(data: bytes, passphrase: str) -> bytes:
    salt, iv, ct = data[1:17], data[17:33], data[33:]
    key = derive_key(passphrase, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpad = padding.PKCS7(128).unpadder()
    return unpad.update(padded) + unpad.finalize()


def password_strength(pw: str) -> tuple[int, str]:
    score = 0
    if len(pw) >= 8:  score += 1
    if len(pw) >= 14: score += 1
    if any(c.isupper() for c in pw) and any(c.islower() for c in pw): score += 1
    if any(c in '0123456789!@#$%^&*' for c in pw): score += 1
    labels = {0: '', 1: 'Weak', 2: 'Fair', 3: 'Strong', 4: 'Very Strong'}
    colors = {0: '#888', 1: '#E24B4A', 2: '#EF9F27', 3: '#639922', 4: '#1D9E75'}
    return score, labels[score], colors[score]


# ─── Main App ─────────────────────────────────────────────────────────────────

class CipherVault(tk.Tk):
    BG      = '#F8F7F2'
    SURFACE = '#FFFFFF'
    BORDER  = '#E0DDD5'
    TEXT    = '#1A1A18'
    MUTED   = '#888880'
    ACCENT  = '#1A1A18'
    MONO    = ('Courier New', 10)
    SANS    = ('Segoe UI', 10)

    def __init__(self):
        super().__init__()
        self.title('CipherVault  —  AES-256 Encryption Tool')
        self.geometry('720x680')
        self.resizable(True, True)
        self.configure(bg=self.BG)
        self.current_file = None
        self._build_ui()

    # ── UI builder ────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=self.SURFACE, height=64,
                       highlightthickness=1, highlightbackground=self.BORDER)
        hdr.pack(fill='x', padx=0, pady=0)
        hdr.pack_propagate(False)

        inner = tk.Frame(hdr, bg=self.SURFACE)
        inner.pack(side='left', padx=20, pady=12)

        icon_box = tk.Frame(inner, bg=self.ACCENT, width=38, height=38)
        icon_box.pack(side='left', padx=(0, 12))
        icon_box.pack_propagate(False)
        tk.Label(icon_box, text='🔒', bg=self.ACCENT, font=('Segoe UI', 16)).place(relx=.5, rely=.5, anchor='center')

        tk.Label(inner, text='CipherVault', bg=self.SURFACE,
                 font=('Courier New', 15, 'bold'), fg=self.TEXT).pack(anchor='w')
        tk.Label(inner, text='AES-256  ·  File & Text Encryption',
                 bg=self.SURFACE, font=('Segoe UI', 9), fg=self.MUTED).pack(anchor='w')

        badge = tk.Label(hdr, text='AES-256', bg=self.BG, fg=self.MUTED,
                         font=('Courier New', 9, 'bold'), padx=10, pady=4,
                         relief='flat', bd=0)
        badge.pack(side='right', padx=20, pady=18)

        # Notebook tabs
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('Custom.TNotebook', background=self.BG, borderwidth=0, tabmargins=0)
        style.configure('Custom.TNotebook.Tab', background=self.BG, foreground=self.MUTED,
                        font=('Segoe UI', 10), padding=[18, 8], borderwidth=0)
        style.map('Custom.TNotebook.Tab',
                  background=[('selected', self.SURFACE)],
                  foreground=[('selected', self.TEXT)])

        tab_bar = tk.Frame(self, bg=self.BG)
        tab_bar.pack(fill='x', padx=20, pady=(14, 0))

        self.nb = ttk.Notebook(tab_bar, style='Custom.TNotebook')
        self.nb.pack(fill='x')

        self.tab_text    = tk.Frame(self.nb, bg=self.SURFACE, padx=24, pady=20)
        self.tab_file    = tk.Frame(self.nb, bg=self.SURFACE, padx=24, pady=20)
        self.tab_decrypt = tk.Frame(self.nb, bg=self.SURFACE, padx=24, pady=20)
        self.nb.add(self.tab_text,    text='  📝  Encrypt Text  ')
        self.nb.add(self.tab_file,    text='  📁  Encrypt File  ')
        self.nb.add(self.tab_decrypt, text='  🔓  Decrypt  ')

        card = tk.Frame(self, bg=self.SURFACE,
                        highlightthickness=1, highlightbackground=self.BORDER)
        card.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        self.nb.pack_forget()

        self.nb2 = ttk.Notebook(card, style='Custom.TNotebook')
        self.nb2.pack(fill='both', expand=True)
        for t, lbl in [(self.tab_text, '  📝  Encrypt Text  '),
                       (self.tab_file, '  📁  Encrypt File  '),
                       (self.tab_decrypt, '  🔓  Decrypt  ')]:
            t2 = tk.Frame(self.nb2, bg=self.SURFACE, padx=24, pady=20)
            self.nb2.add(t2, text=lbl)
            if lbl.strip().startswith('📝'):   self._build_text_tab(t2)
            elif lbl.strip().startswith('📁'): self._build_file_tab(t2)
            else:                               self._build_decrypt_tab(t2)

        # Status bar
        self.status_var = tk.StringVar(value='Ready')
        sb = tk.Frame(self, bg=self.BG)
        sb.pack(fill='x', side='bottom', padx=20, pady=(0, 10))
        tk.Label(sb, textvariable=self.status_var, bg=self.BG,
                 font=('Segoe UI', 9), fg=self.MUTED).pack(side='left')

    # ── Widget helpers ────────────────────────────────────────────────────────

    def _label(self, parent, text):
        tk.Label(parent, text=text, bg=self.SURFACE, fg=self.MUTED,
                 font=('Courier New', 9, 'bold')).pack(anchor='w', pady=(10, 2))

    def _textarea(self, parent, height=6, placeholder=''):
        frame = tk.Frame(parent, bg=self.BORDER, bd=0)
        frame.pack(fill='x', pady=(0, 4))
        txt = tk.Text(frame, height=height, font=self.MONO, bd=0,
                      bg='#F4F3EE', fg=self.TEXT, insertbackground=self.TEXT,
                      relief='flat', padx=10, pady=8, wrap='word',
                      selectbackground='#C8E6FF')
        txt.pack(fill='x', padx=1, pady=1)
        if placeholder:
            txt.insert('1.0', placeholder)
            txt.config(fg=self.MUTED)
            def on_focus_in(e):
                if txt.get('1.0', 'end-1c') == placeholder:
                    txt.delete('1.0', 'end'); txt.config(fg=self.TEXT)
            def on_focus_out(e):
                if not txt.get('1.0', 'end-1c').strip():
                    txt.insert('1.0', placeholder); txt.config(fg=self.MUTED)
            txt.bind('<FocusIn>', on_focus_in)
            txt.bind('<FocusOut>', on_focus_out)
        return txt

    def _passfield(self, parent, on_change=None):
        row = tk.Frame(parent, bg=self.SURFACE)
        row.pack(fill='x', pady=(0, 2))
        frame = tk.Frame(row, bg=self.BORDER)
        frame.pack(side='left', fill='x', expand=True)
        var = tk.StringVar()
        entry = tk.Entry(frame, textvariable=var, show='●', font=self.SANS,
                         bd=0, bg='#F4F3EE', fg=self.TEXT, relief='flat',
                         insertbackground=self.TEXT)
        entry.pack(fill='x', padx=(10, 36), ipady=7)

        visible = [False]
        def toggle():
            visible[0] = not visible[0]
            entry.config(show='' if visible[0] else '●')
            eye_btn.config(text='🙈' if visible[0] else '👁')
        eye_btn = tk.Button(frame, text='👁', bg='#F4F3EE', bd=0, relief='flat',
                            cursor='hand2', command=toggle, font=('Segoe UI', 11))
        eye_btn.place(relx=1.0, rely=0.5, anchor='e', x=-6)

        if on_change:
            var.trace_add('write', lambda *_: on_change(var.get()))
        return var

    def _algo_selector(self, parent):
        row = tk.Frame(parent, bg=self.SURFACE)
        row.pack(anchor='w', pady=(0, 6))
        var = tk.StringVar(value='AES-GCM')
        for val, lbl in [('AES-GCM', 'AES-256-GCM  (Authenticated)'),
                         ('AES-CBC', 'AES-256-CBC')]:
            tk.Radiobutton(row, text=lbl, variable=var, value=val,
                           bg=self.SURFACE, fg=self.TEXT,
                           selectcolor=self.SURFACE, activebackground=self.SURFACE,
                           font=('Segoe UI', 10)).pack(side='left', padx=(0, 16))
        return var

    def _action_btn(self, parent, text, cmd, color=None):
        bg = color or self.ACCENT
        fg = '#FFFFFF'
        btn = tk.Button(parent, text=text, command=cmd,
                        bg=bg, fg=fg, activebackground='#3A3A36',
                        activeforeground=fg, relief='flat', cursor='hand2',
                        font=('Segoe UI', 11, 'bold'), padx=24, pady=10)
        btn.pack(fill='x', pady=(10, 4))
        return btn

    def _strength_bar(self, parent):
        row = tk.Frame(parent, bg=self.SURFACE)
        row.pack(fill='x', pady=(4, 0))
        segs = []
        bar_row = tk.Frame(row, bg=self.SURFACE)
        bar_row.pack(fill='x')
        for _ in range(4):
            seg = tk.Frame(bar_row, bg=self.BORDER, height=4, width=50)
            seg.pack(side='left', padx=2)
            segs.append(seg)
        lbl = tk.Label(row, text='', bg=self.SURFACE, font=('Segoe UI', 9), fg=self.MUTED)
        lbl.pack(anchor='w', pady=(2, 0))

        def update(pw):
            score, label, color = password_strength(pw)
            for i, seg in enumerate(segs):
                seg.config(bg=color if i < score else self.BORDER)
            lbl.config(text=label)
        return update

    def _output_area(self, parent):
        self._label(parent, 'OUTPUT')
        frame = tk.Frame(parent, bg=self.BORDER)
        frame.pack(fill='x')
        out = tk.Text(frame, height=5, font=self.MONO, bd=0,
                      bg='#F4F3EE', fg=self.TEXT, state='disabled',
                      relief='flat', padx=10, pady=8, wrap='word')
        out.pack(fill='x', padx=1, pady=1)

        btn_row = tk.Frame(parent, bg=self.SURFACE)
        btn_row.pack(anchor='w', pady=4)

        def copy():
            txt = out.get('1.0', 'end-1c')
            if txt:
                self.clipboard_clear(); self.clipboard_append(txt)
                self.set_status('✓ Copied to clipboard')

        def save():
            txt = out.get('1.0', 'end-1c')
            if not txt: return
            path = filedialog.asksaveasfilename(defaultextension='.txt',
                filetypes=[('Text file','*.txt'), ('All files','*.*')])
            if path:
                with open(path, 'w') as f: f.write(txt)
                self.set_status(f'✓ Saved to {os.path.basename(path)}')

        for lbl, cmd in [('📋  Copy', copy), ('💾  Save', save)]:
            tk.Button(btn_row, text=lbl, command=cmd,
                      bg=self.BG, fg=self.TEXT, relief='flat',
                      cursor='hand2', font=('Segoe UI', 9),
                      padx=12, pady=5).pack(side='left', padx=(0, 6))
        return out

    def _write_output(self, widget, text):
        widget.config(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', text)
        widget.config(state='disabled')

    def set_status(self, msg):
        self.status_var.set(msg)
        self.after(4000, lambda: self.status_var.set('Ready'))

    # ── Text Encrypt Tab ──────────────────────────────────────────────────────

    def _build_text_tab(self, parent):
        self._label(parent, 'PLAINTEXT')
        self.txt_input = self._textarea(parent, height=6, placeholder='Enter text to encrypt…')

        self._label(parent, 'PASSPHRASE')
        update_bar = self._strength_bar(parent)
        self.txt_pass = self._passfield(parent, on_change=update_bar)

        self._label(parent, 'ALGORITHM')
        self.txt_algo = self._algo_selector(parent)

        self._action_btn(parent, '🔒  Encrypt', self._do_encrypt_text)
        self.txt_output = self._output_area(parent)

    def _do_encrypt_text(self):
        text = self.txt_input.get('1.0', 'end-1c').strip()
        pw   = self.txt_pass.get().strip()
        algo = self.txt_algo.get()
        if not text or text == 'Enter text to encrypt…':
            messagebox.showwarning('Missing input', 'Please enter text to encrypt.'); return
        if not pw:
            messagebox.showwarning('Missing passphrase', 'Please enter a passphrase.'); return
        try:
            fn = encrypt_aes_gcm if algo == 'AES-GCM' else encrypt_aes_cbc
            ct = base64.b64encode(fn(text.encode(), pw)).decode()
            self._write_output(self.txt_output, ct)
            self.set_status(f'✓ Encrypted with {algo}')
        except Exception as e:
            messagebox.showerror('Encryption Error', str(e))

    # ── File Encrypt Tab ──────────────────────────────────────────────────────

    def _build_file_tab(self, parent):
        self._label(parent, 'SELECT FILE')

        drop_frame = tk.Frame(parent, bg='#F4F3EE',
                              highlightthickness=1, highlightbackground=self.BORDER)
        drop_frame.pack(fill='x', pady=(0, 6))

        self.file_label = tk.Label(drop_frame, text='📂  Click to browse a file',
                                   bg='#F4F3EE', fg=self.MUTED,
                                   font=('Segoe UI', 11), pady=20, cursor='hand2')
        self.file_label.pack(fill='x')
        self.file_label.bind('<Button-1>', lambda _: self._browse_file())

        self._label(parent, 'PASSPHRASE')
        self.file_pass = self._passfield(parent)

        self._label(parent, 'ALGORITHM')
        self.file_algo = self._algo_selector(parent)

        self._action_btn(parent, '🔒  Encrypt & Save File', self._do_encrypt_file)

        self.file_progress = ttk.Progressbar(parent, mode='indeterminate')
        self.file_progress.pack(fill='x', pady=(6, 0))

    def _browse_file(self):
        path = filedialog.askopenfilename(title='Select file to encrypt')
        if path:
            self.current_file = path
            name = os.path.basename(path)
            size = os.path.getsize(path)
            self.file_label.config(
                text=f'📄  {name}  ({size/1024:.1f} KB)',
                fg=self.TEXT)

    def _do_encrypt_file(self):
        if not self.current_file:
            messagebox.showwarning('No file', 'Please select a file first.'); return
        pw = self.file_pass.get().strip()
        if not pw:
            messagebox.showwarning('Missing passphrase', 'Please enter a passphrase.'); return
        algo = self.file_algo.get()

        out_path = filedialog.asksaveasfilename(
            title='Save encrypted file',
            initialfile=os.path.basename(self.current_file) + '.enc',
            defaultextension='.enc',
            filetypes=[('Encrypted file', '*.enc'), ('All files', '*.*')])
        if not out_path: return

        self.file_progress.start(10)
        self.set_status('Encrypting…')

        def run():
            try:
                with open(self.current_file, 'rb') as f:
                    data = f.read()
                fn = encrypt_aes_gcm if algo == 'AES-GCM' else encrypt_aes_cbc
                ct = fn(data, pw)
                with open(out_path, 'wb') as f:
                    f.write(ct)
                self.after(0, lambda: (
                    self.file_progress.stop(),
                    self.set_status(f'✓ Saved → {os.path.basename(out_path)}'),
                    messagebox.showinfo('Done', f'File encrypted successfully!\n\n→ {out_path}')
                ))
            except Exception as e:
                self.after(0, lambda: (
                    self.file_progress.stop(),
                    messagebox.showerror('Error', str(e))
                ))

        threading.Thread(target=run, daemon=True).start()

    # ── Decrypt Tab ───────────────────────────────────────────────────────────

    def _build_decrypt_tab(self, parent):
        PAD = 16  # equal inner padding for both columns

        # Outer wrapper — centred with equal side margins
        wrapper = tk.Frame(parent, bg=self.SURFACE)
        wrapper.pack(fill='both', expand=True, padx=0, pady=0)
        wrapper.columnconfigure(0, weight=1, uniform='col')
        wrapper.columnconfigure(2, weight=1, uniform='col')

        # ── Left column: Text decrypt ──
        left = tk.Frame(wrapper, bg=self.SURFACE)
        left.grid(row=0, column=0, sticky='nsew', padx=(0, PAD), pady=0)

        tk.Label(left, text='TEXT DECRYPTION', bg=self.SURFACE, fg=self.TEXT,
                 font=('Courier New', 10, 'bold')).pack(anchor='w', pady=(0, 6))

        self._label(left, 'CIPHERTEXT (BASE64)')
        self.dec_input = self._textarea(left, height=7, placeholder='Paste encrypted text here…')

        self._label(left, 'PASSPHRASE')
        self.dec_pass = self._passfield(left)

        self._action_btn(left, '🔓  Decrypt Text', self._do_decrypt_text)
        self.dec_output = self._output_area(left)

        # ── Vertical divider ──
        tk.Frame(wrapper, bg=self.BORDER, width=1).grid(
            row=0, column=1, sticky='ns', padx=0)

        # ── Right column: File decrypt ──
        right = tk.Frame(wrapper, bg=self.SURFACE)
        right.grid(row=0, column=2, sticky='nsew', padx=(PAD, 0), pady=0)

        tk.Label(right, text='FILE DECRYPTION', bg=self.SURFACE, fg=self.TEXT,
                 font=('Courier New', 10, 'bold')).pack(anchor='w', pady=(0, 6))

        self._label(right, 'SELECT ENCRYPTED FILE')
        drop = tk.Frame(right, bg='#F4F3EE',
                        highlightthickness=1, highlightbackground=self.BORDER)
        drop.pack(fill='x', pady=(0, 6))
        self.dec_file_lbl = tk.Label(drop, text='📂  Click to browse .enc file',
                                     bg='#F4F3EE', fg=self.MUTED,
                                     font=('Segoe UI', 10), pady=18, cursor='hand2')
        self.dec_file_lbl.pack(fill='x', padx=10)
        self.dec_file_lbl.bind('<Button-1>', lambda _: self._browse_enc_file())
        drop.bind('<Button-1>', lambda _: self._browse_enc_file())

        self._label(right, 'PASSPHRASE')
        self.dec_file_pass = self._passfield(right)

        self._action_btn(right, '🔓  Decrypt File & Save', self._do_decrypt_file)

        # File decrypt status label
        self.dec_file_status = tk.Label(right, text='', bg=self.SURFACE,
                                        fg='#1D9E75', font=('Segoe UI', 9))
        self.dec_file_status.pack(anchor='w', pady=(4, 0))

        # Info note
        tk.Label(right,
                 text='Supports files encrypted by\nthe Encrypt File tab (.enc format).',
                 bg=self.SURFACE, fg=self.MUTED, font=('Segoe UI', 9),
                 justify='left').pack(anchor='w', pady=(16, 0))

    def _browse_enc_file(self):
        path = filedialog.askopenfilename(
            title='Select encrypted file',
            filetypes=[('Encrypted file', '*.enc'), ('All files', '*.*')])
        if path:
            self.dec_file = path
            self.dec_file_lbl.config(text=f'📄  {os.path.basename(path)}', fg=self.TEXT)

    def _do_decrypt_text(self):
        cipher = self.dec_input.get('1.0', 'end-1c').strip()
        pw     = self.dec_pass.get().strip()
        if not cipher or cipher == 'Paste encrypted text here…':
            messagebox.showwarning('Missing input', 'Please paste ciphertext.'); return
        if not pw:
            messagebox.showwarning('Missing passphrase', 'Please enter a passphrase.'); return
        try:
            raw = base64.b64decode(cipher)
            fn  = decrypt_aes_gcm if raw[0] == 1 else decrypt_aes_cbc
            plain = fn(raw, pw).decode()
            self._write_output(self.dec_output, plain)
            self.set_status('✓ Decrypted successfully')
        except Exception:
            messagebox.showerror('Decryption Failed',
                'Incorrect passphrase or corrupted/invalid ciphertext.')

    def _do_decrypt_file(self):
        if not hasattr(self, 'dec_file'):
            messagebox.showwarning('No file', 'Please select an encrypted file.'); return
        pw = self.dec_file_pass.get().strip()
        if not pw:
            messagebox.showwarning('Missing passphrase', 'Please enter a passphrase.'); return

        base = os.path.basename(self.dec_file)
        default_name = base[:-4] if base.endswith('.enc') else 'decrypted_' + base
        out_path = filedialog.asksaveasfilename(
            title='Save decrypted file', initialfile=default_name,
            filetypes=[('All files', '*.*')])
        if not out_path: return

        self.set_status('Decrypting…')

        def run():
            try:
                with open(self.dec_file, 'rb') as f:
                    data = f.read()
                fn = decrypt_aes_gcm if data[0] == 1 else decrypt_aes_cbc
                plain = fn(data, pw)
                with open(out_path, 'wb') as f:
                    f.write(plain)
                self.after(0, lambda p=out_path: (
                    self.set_status(f'✓ Saved → {os.path.basename(p)}'),
                    self.dec_file_status.config(text=f'✓ Saved: {os.path.basename(p)}'),
                    messagebox.showinfo('Done', f'File decrypted successfully!\n\n→ {p}')
                ))
            except Exception:
                self.after(0, lambda: messagebox.showerror(
                    'Decryption Failed',
                    'Incorrect passphrase or corrupted file.'))

        threading.Thread(target=run, daemon=True).start()


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    app = CipherVault()
    app.mainloop()
