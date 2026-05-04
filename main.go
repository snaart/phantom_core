package main

import (
	"fmt"
	"image/color"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	// Импортируйте ваш пакет ядра.
	// Если пакет называется phantomcore и находится в папке client:
	"phantom/client/phantom_core"
	// Замените путь импорта на актуальный для вашего go.mod
)

// Global constants
const (
	AppName       = "Phantom Desktop"
	StorageDir    = "./phantom_storage"
	DefaultServer = "127.0.0.1:50051"
)

// PhantomGUI реализует CoreEventHandler и управляет UI
type PhantomGUI struct {
	app  fyne.App
	win  fyne.Window
	core *phantomcore.Core

	// UI Components
	contactsList  *widget.List
	chatContainer *fyne.Container
	chatScroll    *container.Scroll
	messageInput  *widget.Entry
	statusLabel   *widget.Label
	logEntry      *widget.Entry

	// State
	contacts       []phantomcore.ContactInfo
	activePeerHash string
	activePeerName string
}

// --- Реализация CoreEventHandler ---

func (ui *PhantomGUI) OnLog(level phantomcore.LogLevel, message string) {
	prefix := "[INFO]"
	switch level {
	case phantomcore.LogLevelWarning:
		prefix = "[WARN]"
	case phantomcore.LogLevelError:
		prefix = "[ERR]"
	case phantomcore.LogLevelCritical:
		prefix = "[CRIT]"
	}

	fullMsg := fmt.Sprintf("%s %s: %s\n", time.Now().Format("15:04:05"), prefix, message)

	// Обновляем UI в главном потоке
	ui.app.Driver().RunOnUIThread(func() {
		if ui.logEntry != nil {
			ui.logEntry.Append(fullMsg)
		}
		fmt.Print(fullMsg) // Дублируем в консоль
	})
}

func (ui *PhantomGUI) OnMessageReceived(msg phantomcore.StoredMessage) {
	ui.app.Driver().RunOnUIThread(func() {
		// Если сообщение от текущего собеседника, добавляем его в чат
		if msg.SessionHash == ui.activePeerHash {
			ui.addMessageBubble(msg)
			ui.chatScroll.ScrollToBottom()
		} else {
			// Иначе показываем уведомление
			ui.app.SendNotification(fyne.NewNotification("Новое сообщение", msg.Content))
		}
		// Можно обновить список контактов, чтобы поднять активного вверх (если логика позволяет)
	})
}

func (ui *PhantomGUI) OnContactListUpdated(contacts []phantomcore.ContactInfo) {
	ui.contacts = contacts
	ui.app.Driver().RunOnUIThread(func() {
		if ui.contactsList != nil {
			ui.contactsList.Refresh()
		}
	})
}

func (ui *PhantomGUI) OnConnectionStateChanged(state string, err error) {
	ui.app.Driver().RunOnUIThread(func() {
		statusText := fmt.Sprintf("Статус: %s", state)
		if err != nil {
			statusText += fmt.Sprintf(" (%v)", err)
		}
		if ui.statusLabel != nil {
			ui.statusLabel.SetText(statusText)
		}
	})
}

func (ui *PhantomGUI) OnSessionEstablished(peerHash string) {
	ui.OnLog(phantomcore.LogLevelInfo, "Сессия установлена с "+peerHash)
	// Принудительно обновляем список контактов
	if ui.core != nil {
		ui.core.ForceContactSync()
	}
}

func (ui *PhantomGUI) OnShutdown(message string) {
	ui.app.Driver().RunOnUIThread(func() {
		dialog.ShowInformation("Shutdown", message, ui.win)
	})
}

func (ui *PhantomGUI) OnP2PStateChanged(isActive bool, peers []string) {
	ui.app.Driver().RunOnUIThread(func() {
		txt := "P2P: Off"
		if isActive {
			txt = fmt.Sprintf("P2P: On (%d peers)", len(peers))
		}
		if ui.statusLabel != nil {
			// Можно добавить в статус бар, пока просто логируем
			ui.OnLog(phantomcore.LogLevelInfo, "P2P State Update: "+txt)
		}
	})
}

// --- UI Construction ---

func main() {
	myApp := app.NewWithID("com.snaart.phantom")
	myWindow := myApp.NewWindow(AppName)

	gui := &PhantomGUI{
		app: myApp,
		win: myWindow,
	}

	gui.showLoginScreen()

	myWindow.Resize(fyne.NewSize(900, 600))
	myWindow.CenterOnScreen()
	myWindow.ShowAndRun()
}

func (ui *PhantomGUI) showLoginScreen() {
	title := widget.NewLabelWithStyle("Phantom Secure Messenger", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Username (display only)")
	usernameEntry.Text = "User"

	pinEntry := widget.NewPasswordEntry()
	pinEntry.SetPlaceHolder("Enter PIN")

	serverEntry := widget.NewEntry()
	serverEntry.SetPlaceHolder("Server Address")
	serverEntry.Text = DefaultServer

	loginBtn := widget.NewButton("Unlock / Create Account", func() {
		if len(pinEntry.Text) < 4 {
			dialog.ShowError(fmt.Errorf("PIN must be at least 4 chars"), ui.win)
			return
		}

		// Инициализация Core
		core, err := phantomcore.NewCore(usernameEntry.Text, pinEntry.Text, StorageDir, ui)
		if err != nil {
			dialog.ShowError(fmt.Errorf("Failed to init core: %v", err), ui.win)
			return
		}
		ui.core = core

		// Запуск Core в горутине
		go func() {
			err := core.Start(serverEntry.Text, phantomcore.Auto)
			if err != nil {
				ui.OnLog(phantomcore.LogLevelError, "Connection failed: "+err.Error())
				// Не блокируем вход, даем читать историю, но показываем ошибку
			}
		}()

		ui.showMainInterface()
	})

	form := container.NewVBox(
		title,
		widget.NewSeparator(),
		widget.NewLabel("Username:"),
		usernameEntry,
		widget.NewLabel("PIN:"),
		pinEntry,
		widget.NewLabel("Server:"),
		serverEntry,
		layout.NewSpacer(),
		loginBtn,
		layout.NewSpacer(),
	)

	ui.win.SetContent(container.NewCenter(container.NewPadded(form)))
}

func (ui *PhantomGUI) showMainInterface() {
	// 1. Sidebar (Contacts)
	ui.contactsList = widget.NewList(
		func() int { return len(ui.contacts) },
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewIcon(theme.AccountIcon()),
				widget.NewLabel("Contact Name"),
				layout.NewSpacer(),
				widget.NewIcon(theme.MediaRecordIcon()), // Status dot
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			c := ui.contacts[id]
			box := obj.(*fyne.Container)
			label := box.Objects[1].(*widget.Label)
			statusIcon := box.Objects[3].(*widget.Icon)

			label.SetText(c.Name)
			if c.Name == "" {
				label.SetText(c.Hash[:8] + "...")
			}

			// Simple online/offline indicator
			if c.IsOnline || c.IsP2P {
				statusIcon.SetResource(theme.MediaRecordIcon()) // Filled circle
				// Можно менять цвет, если кастомизировать тему, но стандартно просто иконка
			} else {
				statusIcon.SetResource(theme.ViewFullScreenIcon()) // Empty circle imitation or other icon
			}
		},
	)

	ui.contactsList.OnSelected = func(id widget.ListItemID) {
		selected := ui.contacts[id]
		ui.loadChat(selected.Hash, selected.Name)
	}

	// Загружаем контакты при старте
	go func() {
		contacts, err := ui.core.GetContacts()
		if err == nil {
			ui.OnContactListUpdated(contacts)
		}
	}()

	sidebar := container.NewBorder(
		container.NewPadded(widget.NewLabelWithStyle("Contacts", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})),
		container.NewVBox(
			widget.NewButtonWithIcon("Add Contact", theme.ContentAddIcon(), ui.showAddContactDialog),
			widget.NewButtonWithIcon("My Invite", theme.QrcodeIcon(), ui.showMyInviteDialog),
		),
		nil, nil,
		ui.contactsList,
	)

	// 2. Chat Area
	ui.chatContainer = container.NewVBox() // Will hold message bubbles
	ui.chatScroll = container.NewVScroll(ui.chatContainer)

	ui.messageInput = widget.NewEntry()
	ui.messageInput.SetPlaceHolder("Type a message...")
	ui.messageInput.OnSubmitted = func(s string) { ui.sendMessage() }

	sendBtn := widget.NewButtonWithIcon("", theme.MailSendIcon(), ui.sendMessage)

	inputBar := container.NewBorder(nil, nil, nil, sendBtn, ui.messageInput)

	// Status Bar
	ui.statusLabel = widget.NewLabel("Disconnected")
	ui.logEntry = widget.NewMultiLineEntry()
	ui.logEntry.Disable()
	ui.logEntry.SetMinRowsVisible(3)

	// Tabs for Chat and Logs
	chatTab := container.NewBorder(nil, inputBar, nil, nil, ui.chatScroll)
	logsTab := container.NewScroll(ui.logEntry)

	tabs := container.NewAppTabs(
		container.NewTabItem("Chat", chatTab),
		container.NewTabItem("System Logs", logsTab),
	)

	// Split Container
	split := container.NewHSplit(sidebar, tabs)
	split.SetOffset(0.3) // 30% width for sidebar

	ui.win.SetContent(split)
}

func (ui *PhantomGUI) loadChat(hash, name string) {
	ui.activePeerHash = hash
	ui.activePeerName = name
	ui.chatContainer.Objects = nil // Clear current messages

	// Load history
	history, err := ui.core.GetHistory(hash, 50)
	if err != nil {
		ui.OnLog(phantomcore.LogLevelError, "Failed to load history: "+err.Error())
	}

	for _, msg := range history {
		ui.addMessageBubble(msg)
	}

	// Scroll to bottom needs to happen after layout update
	ui.chatScroll.Refresh()
	ui.chatScroll.ScrollToBottom()
}

func (ui *PhantomGUI) sendMessage() {
	text := ui.messageInput.Text
	if text == "" || ui.activePeerHash == "" {
		return
	}

	err := ui.core.SendMessage(ui.activePeerHash, text)
	if err != nil {
		dialog.ShowError(err, ui.win)
		return
	}

	// Add to UI immediately (optimistic)
	msg := phantomcore.StoredMessage{
		SessionHash: ui.activePeerHash,
		IsOutgoing:  true,
		Timestamp:   time.Now().Unix(),
		Content:     text,
	}
	ui.addMessageBubble(msg)

	ui.messageInput.SetText("")
	ui.chatScroll.ScrollToBottom()
}

func (ui *PhantomGUI) addMessageBubble(msg phantomcore.StoredMessage) {
	// Дизайн пузырька
	label := widget.NewLabel(msg.Content)
	label.Wrapping = fyne.TextWrapWord

	var bg *canvas.Rectangle
	var align layout.Direction

	if msg.IsOutgoing {
		// Синий для исходящих
		bg = canvas.NewRectangle(color.RGBA{R: 64, G: 160, B: 255, A: 255})
		align = layout.NewSpacer().(layout.Direction) // Hacky right align attempt
	} else {
		// Серый для входящих
		bg = canvas.NewRectangle(color.RGBA{R: 80, G: 80, B: 80, A: 255})
		align = layout.Direction(0) // Left align
	}
	bg.CornerRadius = 8

	// Компоновка пузырька
	// Note: Fyne doesn't have a super simple "Chat Bubble" widget, creating a custom container stack
	bubble := container.NewStack(bg, container.NewPadded(label))

	// Контейнер для выравнивания (слева или справа)
	var row *fyne.Container
	timeLabel := widget.NewLabelWithStyle(
		time.Unix(msg.Timestamp, 0).Format("15:04"),
		fyne.TextAlignCenter,
		fyne.TextStyle{Monospace: true},
	)

	if msg.IsOutgoing {
		// Right aligned
		row = container.NewHBox(layout.NewSpacer(), timeLabel, bubble)
	} else {
		// Left aligned
		row = container.NewHBox(bubble, timeLabel, layout.NewSpacer())
	}

	ui.chatContainer.Add(row)
}

// --- Dialogs ---

func (ui *PhantomGUI) showAddContactDialog() {
	input := widget.NewMultiLineEntry()
	input.SetPlaceHolder("Paste invite code here...")
	input.SetMinRowsVisible(5)

	dialog.ShowCustomConfirm("Add Contact", "Add", "Cancel", input, func(confirm bool) {
		if confirm && input.Text != "" {
			err := ui.core.ProcessInvite(input.Text)
			if err != nil {
				dialog.ShowError(err, ui.win)
			} else {
				dialog.ShowInformation("Success", "Contact added successfully!", ui.win)
				// Refresh list
				contacts, _ := ui.core.GetContacts()
				ui.OnContactListUpdated(contacts)
			}
		}
	}, ui.win)
}

func (ui *PhantomGUI) showMyInviteDialog() {
	// Display name input
	entry := widget.NewEntry()
	entry.SetPlaceHolder("Your Display Name")
	entry.Text = "Phantom User"

	dialog.ShowCustomConfirm("Generate Invite", "Generate", "Cancel", entry, func(confirm bool) {
		if confirm {
			code, err := ui.core.CreateInvite(entry.Text)
			if err != nil {
				dialog.ShowError(err, ui.win)
				return
			}

			// Show code with copy button
			codeEntry := widget.NewMultiLineEntry()
			codeEntry.SetText(code)
			codeEntry.Wrapping = fyne.TextWrapBreak
			codeEntry.Disable() // Read only

			copyBtn := widget.NewButtonWithIcon("Copy to Clipboard", theme.ContentCopyIcon(), func() {
				ui.win.Clipboard().SetContent(code)
			})

			content := container.NewBorder(nil, copyBtn, nil, nil, codeEntry)
			dialog.ShowCustom("Your Invite Code", "Close", content, ui.win)
		}
	}, ui.win)
}
