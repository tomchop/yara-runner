// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';

type YaraDirective = {
	type: string,
	mode: string
};

// this method is called when your extension is activated
// your extension is activated the very first time the command is executed

const spawn = require("child_process").spawn;
const spawnSync = require("child_process").spawnSync;

const VERSION = 0.1;

export class YaraRunner {

	private output: any;
	private document: any;
	private matchDirectives: Map<string, YaraDirective>;
	private yaraPath: string;
	private hasErrors: boolean;
	private config: any;


	constructor() {
		this.output = vscode.window.createOutputChannel("Yara runner");;
		this.document = vscode.window.activeTextEditor?.document;
		this.matchDirectives = new Map();
		this.hasErrors = false;
		this.config = vscode.workspace.getConfiguration("yara-runner");
		this.yaraPath = this.config.get("yaraPath");
	}

	public checkDocument() {
		if (!this.document) {
			return false;
		}
		if (this.document.isUntitled) {
			vscode.window.showErrorMessage('Please save the file before running Yara');
			return false;
		}
		if (this.document.isDirty) {
			vscode.window.showInformationMessage('Document has changes, saving');
			this.document.save();
		}
		return true;
	}

	public checkYara() {
		let cmd = 'yara -v';
		let process = spawnSync(cmd, [], {
			shell: true
		});
		if (process.status !== 0) {
			vscode.window.showErrorMessage(`Yara was not found in PATH (used '${cmd}')`);
			return false;
		}
		this.output.append(`Yara version: ${process.stdout.toString()}`);
		return true;
	}

	public runYara(target: string, isDirectory: boolean, matchExpected: boolean) {

		return new Promise((resolve) => {

			let cmd = `${this.yaraPath} ${this.document.fileName}`;
			if (isDirectory) {
				cmd += ` -r ${target}`;
			} else {
				cmd += ` ${target}`;
			}
			if (matchExpected) {
				cmd += ` -n`;
			}

			console.log('[yara-runner] Running Yara command:', cmd);
			let yaraProcess = spawn(cmd, [], {
				shell: true
			});
			let output = '';

			yaraProcess.stdout.on("data", (data: string) => {
				// this.output.append(data.toString());
				output += data.toString();
			});

			yaraProcess.on("close", (code: number) => {
				if (code !== 0) {
					this.output.appendLine(`Yara errored out with code ${code}\nInvoked using:\n    '${cmd}'`);
					this.hasErrors = true;
					resolve(false);
				}
				if (output.length > 0 && matchExpected) {
					this.output.append(`False negative: ${output}`);
					this.hasErrors = true;
					resolve(false);
				}
				if (output.length > 0 && !matchExpected) {
					this.output.append(`False positive: ${output}`);
					this.hasErrors = true;
					resolve(false);
				}
				resolve(true);
			});

		});


	}

	public async parseMatchRules() {
		let rule = this.document.getText();
		let matches = rule.matchAll(/\/\/ runner-(dir|file)-(match|nomatch): (.*)/g);

		for (let match of matches) {
			console.log(`[yara-runner] Parsed directive: ${match[2]} ${match[1]} at ${match[3]}`);
			try {
				await vscode.workspace.fs.stat(vscode.Uri.file(match[3]));
				this.matchDirectives.set(match[3], {type: match[2], mode: match[1]});
			} catch (err) {
				let msg = `Can't stat() ${match[3]}, skipping.`;
				this.output.appendLine(msg);
				console.log('[yara-runner] ', msg, err.message);
			}
		}
	}

	public runAllYara() {
		this.hasErrors = false;
		let pr = [];

		for ( let [target, settings] of this.matchDirectives) {
			let isDirectory = settings.mode === 'dir';
			let matchExpected = settings.type === 'match';
			let process = this.runYara(target, isDirectory, matchExpected);
			pr.push(process);
		}

		return Promise.allSettled(pr).then(() => {
			if (this.hasErrors) {
				this.output.appendLine(`\n:( Errors found! Tweak your rule and try again.`);
			} else {
				this.output.appendLine(`\n:) No FP or FN found, you're good to go.`);
			}
		});
	}

	public async run() {
		this.output.clear();
		this.output.show(true);
		if (!(this.checkYara() && this.checkDocument())) {
			return;
		}
		await this.parseMatchRules();
		this.output.appendLine(`Runner results ============================`);
		await this.runAllYara();
	}

}

export function activate(context: vscode.ExtensionContext) {

	// Use the console to output diagnostic information (console.log) and errors (console.error)
	// This line of code will only be executed once when your extension is activated
	console.log(`[yara-runner] Yara runner extension ${VERSION} is active.`);
	let yaraRunner = new YaraRunner();

	// The command has been defined in the package.json file
	// Now provide the implementation of the command with registerCommand
	// The commandId parameter must match the command field in package.json
	context.subscriptions.push(vscode.commands.registerCommand('yara-runner.runYara', () => {
		// The code you place here will be executed every time your command is executed
		// Display a message box to the user
		yaraRunner.run();
	}));
}

// this method is called when your extension is deactivated
export function deactivate() {}
