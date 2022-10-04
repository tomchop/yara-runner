/* eslint-disable @typescript-eslint/naming-convention */
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
const http = require("http");

const VERSION = "0.0.2";

export class YaraRunner {

	private output: any;
	private document: any;
	private matchDirectives: Map <string, YaraDirective> ;
	private yaraPath: string;
	private hasErrors: boolean;
	private config: any;

	private vtApiKey: string;
	private retrohuntId: any;


	constructor() {
		this.output = vscode.window.createOutputChannel("Yara runner");;
		this.document = vscode.window.activeTextEditor?.document;
		this.matchDirectives = new Map();
		this.hasErrors = false;
		this.retrohuntId = null;
		this.config = vscode.workspace.getConfiguration("yara-runner");
		this.yaraPath = this.config.get("yaraPath");
		this.vtApiKey = this.config.get("vtApiKey");
	}

	public checkDocument() {
		this.document = vscode.window.activeTextEditor?.document;
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
				this.matchDirectives.set(match[3], {
					type: match[2],
					mode: match[1]
				});
			} catch (err: any) {
				let msg = `Can't stat() ${match[3]}, skipping.`;
				this.output.appendLine(msg);
				console.log('[yara-runner] ', msg, err.message);
			}
		}
	}

	public runAllYara() {
		this.hasErrors = false;
		let pr = [];

		for (let [target, settings] of this.matchDirectives) {
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

	private async getRetrohuntRequest(retrohuntId: string) {
		let headers = {
			"x-apikey": this.vtApiKey,
			"Content-Type": "application/json"
		};

		let uri = `http://www.virustotal.com/api/v3/intelligence/retrohunt_jobs/${retrohuntId}`;

		return new Promise((resolve) => {
			let req = http.get(
				uri, {
					headers: headers
				}, (res: any) => {
					res.setEncoding('utf8');
					let rawData = '';
					res.on('data', (chunk: string) => {
						rawData += chunk;
					});
					res.on('end', () => {
						try {
							const parsedData = JSON.parse(rawData);
							let status = parsedData.data.attributes.status;
							resolve(parsedData);
						} catch (err: any) {
							console.error(err.message);
							console.log(rawData);
						}
					});
				});
		});
	}

	private stripDirectivesFromRule() {
		let text = this.document.getText();
		return text.replace(/\/\/ runner.*$/gm, '');
	}

	public async goodwareHunt() {

		if (this.retrohuntId !== null) {
			this.output.appendLine(`Retrohunt ${this.retrohuntId} already running, please wait for it to finish.`);
			return;
		}

		if (!(this.checkYara() && this.checkDocument())) {
			this.output.appendLine('Failed checks, please make sure the Yara rule is formatted correctly.');
			return;
		}

		this.output.clear();
		this.output.show(true);

		console.log('[yara-runner] New goodware retrohunt requested');
		this.output.appendLine(`Running new retrohunt on VT's goodware corpus...`);

		let options = {
			method: "POST",
			headers: {
				"x-apikey": this.vtApiKey,
				"Content-Type": "application/json"
			}
		};
		const payload = {
			data: {
				type: "retrohunt_job",
				attributes: {
					rules: this.stripDirectivesFromRule(),
					corpus: "goodware"
				}
			}
		};

		// Connect to virustotl API and run a goodware hunt
		let retrohuntId = await new Promise((resolve) => {
			let req = http.request(
				`http://www.virustotal.com/api/v3/intelligence/retrohunt_jobs`, options, (res: any) => {
					res.setEncoding('utf8');
					let rawData = '';
					res.on('data', (chunk: string) => {
						rawData += chunk;
					});
					res.on('end', () => {
						try {
							const parsedData = JSON.parse(rawData);
							this.retrohuntId = parsedData.data.id;
							this.output.appendLine(`Retrohunt started, ID: ${this.retrohuntId}`);
							resolve(this.retrohuntId);
						} catch (err: any) {
							console.log(rawData);
							console.error(err.message);
						}
					});
				});
			req.write(JSON.stringify(payload));
			req.end();
		});

		let result: any = {};
		let progress: number = 0;
		this.output.appendLine(`Progress: 0%`);

		do {
			result = await this.getRetrohuntRequest(this.retrohuntId);
			if (result.data.attributes.progress !== progress) {
				progress = result.data.attributes.progress;
				this.output.appendLine(`Progress: ~${Math.round(progress)}% (${result.data.attributes.num_matches} matches)`);
			}
			await new Promise(r => setTimeout(r, 3000));
		} while (result.data.attributes.status !== 'finished');

		this.output.appendLine(`Goodware retrohunt finished: ${result.data.attributes.num_matches} matches.`);
		let deltaSec = result.data.attributes.finish_date - result.data.attributes.start_date;
		let gbScanned = result.data.attributes.scanned_bytes / (1024 ** 3);
		this.output.appendLine(`Stats: Scanned ${gbScanned.toFixed(2)} GB in ${deltaSec}s.`);
		this.retrohuntId = null;
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

	context.subscriptions.push(vscode.commands.registerCommand('yara-runner.runGoodwareHunt', () => {
		// The code you place here will be executed every time your command is executed
		// Display a message box to the user
		yaraRunner.goodwareHunt();
	}));
}

// this method is called when your extension is deactivated
export function deactivate() {}
