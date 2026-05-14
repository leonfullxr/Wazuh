packer {
  required_plugins {
    qemu = {
      version = "~> 1"
      source  = "github.com/hashicorp/qemu"
    }
    vagrant = {
      version = "~> 1"
      source  = "github.com/hashicorp/vagrant"
    }
  }
}

source "qemu" "rhel8" {
  iso_url           = "./rhel-8.10-x86_64-dvd.iso"
  iso_checksum      = "none" # In production, put the actual SHA256 hash here
  output_directory  = "output-rhel8"
  shutdown_command  = "echo 'vagrant' | sudo -S shutdown -P now"
  disk_size         = "30G"
  format            = "qcow2"
  accelerator       = "tcg"
  headless          = true
  qemu_binary       = "qemu-system-x86_64"
  http_directory    = "http"
  ssh_username      = "vagrant"
  ssh_password      = "vagrant"
  ssh_timeout       = "80m"
  vm_name           = "rhel8-base"
  memory            = 2048
  cpus              = 2
  
  # This types the command into the GRUB bootloader to start the Kickstart
  boot_command = [
    "<tab><wait>",
    " inst.ks=http://{{ .HTTPIP }}:{{ .HTTPPort }}/ks.cfg<enter>"
  ]
}

build {
  sources = ["source.qemu.rhel8"]

  # Package into a Vagrant Box format
  post-processor "vagrant" {
    output = "rhel8-cis-ready.box"
  }
}
