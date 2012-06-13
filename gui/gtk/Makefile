BIN = gui_gtk
$(BIN): gui_gtk.c
	gcc `pkg-config --cflags --libs gtk+-2.0` $^ -o $@ -lnl

clean:
	rm $(BIN)
