---
layout: default
title: "Windows Terminal 配置文件"
tags:
- blog-comments
- Java 反序列化
---

# Windows Terminal 配置文件

```java
// To view the default settings, hold "alt" while clicking on the "Settings" button.
// For documentation on these settings, see: https://aka.ms/terminal-documentation
{
	"$schema": "https://aka.ms/terminal-profiles-schema",
	// 默认打开窗口guid
	"defaultProfile": "{0caa0dad-35be-5f56-a8ff-afceeeaa6101}",
	"profiles": [
		{
			// Make changes here to the cmd.exe profile
			"guid": "{0caa0dad-35be-5f56-a8ff-afceeeaa6101}",
			"name": "CMD",
			"commandline": "cmd.exe",
			"hidden": false,
			"acrylicOpacity": 0.75,
			// 背景图片
			"backgroundImage": "D:\\Git\\icon\\13.jpg",
			"backgroundImageOpacity": 0.9,
			"closeOnExit": true,
			"colorScheme": "CMD",
			//"commandline": "cmd.exe",
			"cursorColor": "#FFFFFF",
			// 光标
			"cursorShape": "underscore",
			"fontFace": "Consolas",
			"fontSize": 12,

			"historySize": 9001,
			"icon": "ms-appx:///ProfileIcons/{0caa0dad-35be-5f56-a8ff-afceeeaa6101}.png",
			//	"name": "cmd",
			"padding": "0, 0, 0, 0",
			"snapOnInput": true,
			// 打开窗口的路径
			"startingDirectory": "./",
			"tabTitle": "CMD",
			"useAcrylic": false
	
		},
	
		{
			// Make changes here to the powershell.exe profile
			"guid": "{61c54bbd-c2c6-5271-96e7-009a87ff44bf}",
			"name": "Windows PowerShell",
			"commandline": "powershell.exe",
			"hidden": false,
	
			"acrylicOpacity": 0.5,
			"background": "#000000",
	
			"backgroundImage": "D:\\Git\\icon\\7s'd.jpg",
	
			"backgroundImageOpacity": 0.9,
	
			"closeOnExit": true,
			"colorScheme": "CMD",
	
			// "commandline": "powershell.exe",
			"cursorColor": "#FFFFFF",
			// 光标
			"cursorShape": "underscore",
			"fontFace": "Consolas",
			"fontSize": 12,
		
			"historySize": 9001,
			"icon": "ms-appx:///ProfileIcons/{61c54bbd-c2c6-5271-96e7-009a87ff44bf}.png",
			"padding": "0, 0, 0, 0",
			"snapOnInput": true,
			"startingDirectory": "./",
			"tabTitle": "Powershell",
			"useAcrylic": true

		},
	
		{
			"guid": "{b453ae62-4e3d-5e58-b989-0a998ec441b8}",
			"hidden": false,
			"name": "Azure Cloud Shell",
			"source": "Windows.Terminal.Azure"
		},
	
		{
			//git-bash
			"tabTitle": "Git-bash",
			"acrylicOpacity": 0.5,
			"backgroundImage": "D:\\Git\\icon\\3.jpg",
			"closeOnExit": true,
			"colorScheme": "Brogrammer",
			"commandline": "D:\\Git\\bin\\bash.exe",
			"cursorColor": "#FFFFFF",
			"cursorShape": "bar",
			"fontFace": "Fira Code Medium",
			"fontSize": 12,
			"guid": "{1c4de342-38b7-51cf-b940-2309a097f489}",
			"historySize": 9001,
			// "icon": "E:\\Git\\git-icon.png", 
			"icon": "D:\\Git\\icon\\1.jpg",
			"name": "Bash",
			"padding": "10, 10, 10, 10",
			"snapOnInput": true,
	
			"startingDirectory": "./",
			"useAcrylic": true
		},
		{
			"tabTitle": "Ubuntu (WSL)",
			//"tabTitle": "Ubuntu (WSL)",
			"acrylicOpacity": 0.1,
			"backgroundImage": "D:\\Git\\icon\\4.jpg",
	
			"backgroundImageOpacity": 0.9,
	
			"closeOnExit": true,
			"colorScheme": "Campbell",
			//"colorScheme": "CMD",
			"commandline": "wsl.exe -d Ubuntu",
			"cursorColor": "#FFFFFF",
			"cursorShape": "bar",
			"fontFace": "Consolas",
			"fontSize": 13,
			"guid": "{2c4de342-38b7-51cf-b940-2309a097f518}",
			"historySize": 9001,
			"icon": "ms-appx:///ProfileIcons/{9acb9455-ca41-5af7-950f-6bca1bc9722f}.png",
			"name": "Ubuntu",
			"padding": "0, 0, 0, 0",
			"snapOnInput": true,
			"useAcrylic": true,
			"startingDirectory": "./"
		}

	],
	
	// Add custom color schemes to this array
	"schemes": [
	
		{
			"background": "#000000",
			"black": "#0C0C0C",
			"blue": "#0037DA",
			"brightBlack": "#767676",
			"brightBlue": "#3B78FF",
			"brightCyan": "#61D6D6",
			"brightGreen": "#16C60C",
			"brightPurple": "#B4009E",
			"brightRed": "#E74856",
			"brightWhite": "#F2F2F2",
			"brightYellow": "#F9F1A5",
			"cyan": "#3A96DD",
			"foreground": "#FFFFFF",
	
			"green": "#13A10E",
			"name": "CMD",
	
			"purple": "#881798",
			"red": "#C50F1F",
			"white": "#CCCCCC",
			"yellow": "#C19C00"
		},
	
		{
			"background": "#000000",
	
			"black": "#0C0C0C",
			"blue": "#0037DA",
			"brightBlack": "#767676",
			"brightBlue": "#3B78FF",
			"brightCyan": "#61D6D6",
			"brightGreen": "#16C60C",
			"brightPurple": "#B4009E",
			"brightRed": "#E74856",
			"brightWhite": "#F2F2F2",
			"brightYellow": "#F9F1A5",
			"cyan": "#3A96DD",
			"foreground": "#FFFFFF",
	
			"green": "#13A10E",
			"name": "Brogrammer",
	
			"purple": "#881798",
			"red": "#C50F1F",
			"white": "#CCCCCC",
			"yellow": "#C19C00"
		}
	
	],
	
	// Add any keybinding overrides to this array.
	// To unbind a default keybinding, set the command to "unbound"
	"keybindings": [
		// 关闭所有的窗口
		{
			"command": "closeWindow",
			"keys": [ "ctrl+q" ]
		},
		// 新建一个窗口
		{
			"command": {
				"action": "newTab",
				"commandline": "",
				"startingDirectory": "./",
				"tabTitle": "CMD",
				"index": 0,
				"profile": "CMD"
			},
			"keys": [ "alt+q" ]
		},
		// 复制快捷键
		{
			"command": {
				"action": "copy",
				"singleLine": false
			},
			"keys": [ "ctrl+c" ]
		},
		// 粘贴快捷键
		{
			"command": "paste",
			"keys": [ "ctrl+v" ]
		}
	]
	// 关闭当前选项卡
	{
		"command": "closeTab",
		"keys": [
			"shift+q"
		]
	}
}
```

# 参考

<https://github.com/microsoft/terminal/blob/master/doc/cascadia/SettingsSchema.md>  
<https://www.cnblogs.com/KiraYoshikage/p/11443741.html>
