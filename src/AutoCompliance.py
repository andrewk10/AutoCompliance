import gi
gi.require_version("Gtk", "4.0")


def on_activate(app):
    win = gi.repository.Gtk.ApplicationWindow(application=app)
    btn = gi.repository.Gtk.Button(label="Hello, World!")
    btn.connect('clicked', lambda x: win.close())
    win.set_child(btn)
    win.present()


app = gi.repository.Gtk.Application(application_id='org.gtk.Example')
app.connect('activate', on_activate)
app.run(None)
