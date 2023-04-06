import { ToasterService } from './core/services/toaster.service';
import { MatSnackBar } from '@angular/material/snack-bar';
import { Component, Injector } from '@angular/core';

@Component({
  selector: 'penny-task-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss'],
})
export class AppComponent {
  snackBar!: MatSnackBar;

  constructor(
    private toasterService: ToasterService,
    public injector: Injector
  ) {
    this.snackBar = injector.get(MatSnackBar);
  }

  ngOnInit() {
    this.toasterService.snack_bar = this.snackBar;
  }
}
