# window.py
#
# Copyright 2022 Andrew
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from gi.repository import Gtk


@Gtk.Template(resource_path='/org/example/App/window.ui')
class AutocomplianceWindow(Gtk.ApplicationWindow):
    __gtype_name__ = 'AutocomplianceWindow'

    label = Gtk.Template.Child()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_title("AutoCompliance")

        box = Gtk.VBox()
        self.set_child(box)

        resource_limiting_btn = Gtk.Button(label='Resource Limiting')
        resource_limiting_btn.connect('clicked', lambda x: self.close())
        # box.(resource_limiting_btn)

        specify_domain_details_btn = Gtk.Button(label='Specify Domain Details')
        specify_domain_details_btn.connect('clicked', lambda x: self.close())
        # self.add(specify_domain_details_btn)

        add_domain_devices_btn = Gtk.Button(label='Add Domain Devices')
        add_domain_devices_btn.connect('clicked', lambda x: self.close())
        # self.add(add_domain_devices_btn)

        provide_brute_force_propagation_information_btn = Gtk.Button(label='Provide Brute-Force Propagation Information')
        provide_brute_force_propagation_information_btn.connect('clicked', lambda x: self.close())
        # self.add(provide_brute_force_propagation_information_btn)




class AboutDialog(Gtk.AboutDialog):

    def __init__(self, parent):
        Gtk.AboutDialog.__init__(self)
        self.props.program_name = 'autocompliance'
        self.props.version = "0.1.0"
        self.props.authors = ['Andrew']
        self.props.copyright = '2022 Andrew'
        self.props.logo_icon_name = 'org.example.App'
        self.props.modal = True
        self.set_transient_for(parent)

