#!/bin/bash
# Author: Jorge Ramirez <jorgeramirez1990@gmail.com>

usage() {

cat << EOF
Loads the sniffer module and executes the gui client. Run this
program as root.

Usage: ./run.sh [optional arguments]

Optional arguments:
    -h, --help               Display help information and exit.

    -f, --front-end <type>   Specify the front end type (defaults to gtk). 
                             If the type value is 'console', it means CLI based interface. 
                             If it is 'gtk', it means gtk based interface.
EOF
    exit
}

options=`getopt -o hf: -l help,front-end:  -n 'run' -- "$@"`

if [ $? !=  0 ] ; then
    echo "Something went wrong. Terminating..." >&2
    exit 1
fi

eval set -- $options

front_end=gui/gtk/gui_gtk
sniffer_module=module/sniffer.ko


while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        -f|--front-end)
            case "$2" in
                console)
                    front_end=gui/console/gui_console
                    ;;
                gtk)
                    front_end=gui/gtk/gui_gtk
                    ;;
                *)
                    echo "The front end value is invalid"
                    usage
                    ;;
            esac
            shift
            ;;
    esac
    shift
done

if [[ $EUID -ne 0  ]]; then
    echo "You must run this command as root" 1>&2
    exit 1
fi

# insert sniffer module
insmod $sniffer_module

# run front end
$front_end

# remove sniffer module
rmmod $sniffer_module
